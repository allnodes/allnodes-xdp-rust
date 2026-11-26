
use {
    crate::{
        context::FailureState,
        error::{DropReason, XdpFailure},
        quic::frame::{self, HEADERS, TxHeader},
        quic::kernel_sock::KernelSock,
        metrics::{Metrics, SocketMetrics, XdpStatistics},
        monitor::{Resolved, Routes, Stopped, TxObs},
        quic::peers::{PeerPath, PeerTable},
        quic::rings::{
            self, RECLAIM_BATCH, RingProbe, RxRing, SERVICE_STEP, TxRing, WakeOutcome,
            classify_wake_error,
        },
        slaves::{Eligibility, pick_slave},
    },
    parking_lot::{Condvar, Mutex},
    quinn::{
        AsyncUdpSocket, UdpPoller,
        udp::{RecvMeta, Transmit},
    },
    std::{
        fmt,
        io::{self, IoSliceMut},
        net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
        os::fd::{AsRawFd, RawFd},
        pin::Pin,
        sync::{
            Arc, Weak,
            atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence},
        },
        task::{Context, Poll, Waker},
        thread::JoinHandle,
        time::{Duration, Instant},
    },
    tokio::io::{Interest, unix::AsyncFd},
};

pub(crate) type RxImpl = rings::XskRx;
pub(crate) type TxImpl = rings::XskTx;
pub(crate) type ProbeImpl = rings::XskProbe;

pub(crate) use crate::quic::pump::Inbox;

pub(crate) const fn own_queue(
    rx: rings::XskRx,
    tx: rings::XskTx,
    probe: rings::XskProbe,
) -> (RxImpl, TxImpl, ProbeImpl) {
    (rx, tx, probe)
}

const fn inert_probe() -> ProbeImpl {
    rings::XskProbe::inert()
}

pub(crate) const PEER_SLOTS: usize = 4096;
const SERVICE_JOIN: Duration = Duration::from_secs(1);

pub(crate) struct WakerSlot {
    set: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl WakerSlot {
    pub(crate) const fn new() -> Self {
        Self {
            set: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    pub(crate) fn register(&self, w: &Waker) {
        let mut g = self.waker.lock();
        let old = match &*g {
            Some(o) if o.will_wake(w) => None,
            _ => g.replace(w.clone()),
        };
        self.set.store(true, Ordering::SeqCst);
        drop(g);
        if let Some(o) = old {
            o.wake();
        }
    }

    pub(crate) fn wake(&self) {
        fence(Ordering::SeqCst);
        if !self.set.load(Ordering::SeqCst) {
            return;
        }
        let w = {
            let mut g = self.waker.lock();
            self.set.store(false, Ordering::SeqCst);
            g.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

#[cold]
pub(crate) fn dropped_since(last_total: &AtomicU64, total: u64) -> u64 {
    total.saturating_sub(last_total.swap(total, Ordering::Relaxed))
}

pub(crate) fn rate_limited(last: &AtomicU64, epoch: Instant) -> bool {
    let now = epoch.elapsed().as_secs() + 1;
    let prev = last.load(Ordering::Relaxed);
    now > prev
        && last
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

const FAILED: u8 = 1;
const DOWN: u8 = 2;

#[derive(Default)]
struct SvcState {
    pending: bool,
    stop: bool,
    exited: bool,
}

pub(crate) struct Hub {
    pub(crate) interface: String,
    state: AtomicU8,
    failure: FailureState,
    sockets: Mutex<Vec<Weak<XdpQuicSocket>>>,
    svc: Mutex<SvcState>,
    svc_cv: Condvar,
    svc_stop: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
    stopped: tokio::sync::watch::Sender<Option<Stopped>>,
    on_drop: Mutex<Option<DropHook>>,
}

pub(crate) type DropHook = Arc<dyn Fn(&'static str) + Send + Sync>;

impl Hub {
    pub(crate) fn new(interface: &str) -> Arc<Self> {
        Arc::new(Self {
            interface: interface.to_string(),
            state: AtomicU8::new(0),
            failure: FailureState::new(),
            sockets: Mutex::new(Vec::new()),
            svc: Mutex::new(SvcState::default()),
            svc_cv: Condvar::new(),
            svc_stop: AtomicBool::new(false),
            thread: Mutex::new(None),
            stopped: tokio::sync::watch::Sender::new(None),
            on_drop: Mutex::new(None),
        })
    }

    pub(crate) fn fail(&self, cause: String) -> bool {
        let logged = cause.clone();
        if !self.failure.fail(cause) {
            return false;
        }
        self.state.fetch_or(FAILED, Ordering::SeqCst);
        tracing::error!(interface = %self.interface, state = "failed", reason = %logged, action = "restart", "XDP context failed");
        if let Some(f) = self.failure.get() {
            self.stopped
                .send_if_modified(|v| v.is_none() && v.replace(Stopped::Failed(f)).is_none());
        }
        self.wake_all();
        true
    }

    pub(crate) fn failed(&self) -> Option<XdpFailure> {
        self.failure.get()
    }

    pub(crate) async fn wait_failed(&self) -> XdpFailure {
        self.failure.wait().await
    }

    pub(crate) fn shut_down(&self) {
        self.state.fetch_or(DOWN, Ordering::SeqCst);
        self.stopped
            .send_if_modified(|v| v.is_none() && v.replace(Stopped::ShutDown).is_none());
        self.wake_all();
    }

    pub(crate) fn retire_sockets(&self) {
        let live: Vec<Arc<XdpQuicSocket>> = self
            .sockets
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for s in live {
            s.retire();
        }
    }

    pub(crate) async fn stopped(&self) -> Stopped {
        let mut rx = self.stopped.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(v) => v.clone().unwrap_or(Stopped::ShutDown),
            Err(_) => Stopped::ShutDown,
        }
    }

    pub(crate) fn set_drop_hook(&self, hook: DropHook) {
        *self.on_drop.lock() = Some(hook);
    }

    pub(crate) fn live_sockets(&self) -> Vec<Arc<XdpQuicSocket>> {
        self.sockets
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    pub(crate) fn tx_progress(&self) -> Vec<TxObs> {
        let mut seen: Vec<usize> = Vec::new();
        let mut out = Vec::new();
        for s in self.live_sockets() {
            for q in s.tx_queues().iter().filter(|q| !q.is_retired()) {
                let at = std::ptr::from_ref(q) as usize;
                if seen.contains(&at) {
                    continue;
                }
                seen.push(at);
                let (submitted, completed) = q.probe.tx_progress();
                out.push(TxObs {
                    device: q.device.clone(),
                    queue: q.queue,
                    submitted,
                    completed,
                });
            }
        }
        out
    }

    pub(crate) fn kick_device(&self, device: &str) {
        self.kick_where(|q| q.device == device);
    }

    pub(crate) fn kick_queue(&self, device: &str, queue: u32) {
        self.kick_where(|q| q.device == device && q.queue == queue);
    }

    fn kick_where(&self, pick: impl Fn(&QueueCore) -> bool) {
        let mut any = false;
        for s in self.live_sockets() {
            for q in s
                .tx_queues()
                .iter()
                .filter(|q| !q.is_retired() && !q.gone.load(Ordering::SeqCst) && pick(q))
            {
                q.tx_kick_pending.store(true, Ordering::SeqCst);
                q.rx_kick_pending.store(true, Ordering::SeqCst);
                if q.is_retired() {
                    q.clear_kicks();
                    continue;
                }
                any = true;
            }
        }
        if any {
            self.signal();
        }
    }

    pub(crate) fn retire_slave(&self, slave: usize) {
        for s in self.live_sockets() {
            s.retire_slave(slave);
        }
    }

    pub(crate) fn eligibility_changed(&self) {
        for s in self.live_sockets() {
            s.wake_waiters();
        }
    }

    #[inline]
    pub(crate) fn check(&self) -> io::Result<()> {
        match self.state.load(Ordering::Acquire) {
            0 => Ok(()),
            s => Err(self.error(s)),
        }
    }

    #[cold]
    fn error(&self, s: u8) -> io::Error {
        match self.failure.get() {
            Some(f) if s & FAILED != 0 => io::Error::other(f.cause),
            _ => io::Error::other("XDP context shut down"),
        }
    }

    #[cold]
    fn down_error(&self) -> io::Error {
        self.check()
            .err()
            .unwrap_or_else(|| io::Error::other("XDP context shut down"))
    }

    fn wake_all(&self) {
        let live: Vec<Arc<XdpQuicSocket>> = self
            .sockets
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for s in live {
            s.reader.wake();
            s.wake_waiters();
        }
    }

    fn register(&self, s: &Arc<XdpQuicSocket>) {
        let mut g = self.sockets.lock();
        g.retain(|w| w.strong_count() > 0);
        g.push(Arc::downgrade(s));
    }

    fn signal(&self) {
        let mut g = self.svc.lock();
        g.pending = true;
        self.svc_cv.notify_all();
    }

    pub(crate) fn start_service(self: &Arc<Self>) -> io::Result<()> {
        let hub = Arc::clone(self);
        let handle = std::thread::Builder::new()
            .name("gun-xdp-svc".into())
            .spawn(move || hub.run_service())?;
        *self.thread.lock() = Some(handle);
        Ok(())
    }

    fn run_service(&self) {
        unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0, 0, 0) };
        tracing::debug!(interface = %self.interface, cpus = %affinity(), state = "ready", "XDP service thread started");
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.service_loop()));
        if run.is_err() {
            self.fail("XDP service thread panicked".into());
        } else {
            let reason = if self.failed().is_some() {
                "context failed"
            } else {
                "shutdown"
            };
            tracing::debug!(interface = %self.interface, state = "stopped", reason, "XDP service thread stopped");
        }
        let mut g = self.svc.lock();
        g.exited = true;
        self.svc_cv.notify_all();
    }

    fn service_loop(&self) {
        let mut live: Vec<Arc<XdpQuicSocket>> = Vec::new();
        loop {
            {
                let mut g = self.svc.lock();
                while !g.pending && !g.stop {
                    self.svc_cv.wait(&mut g);
                }
                if g.stop {
                    return;
                }
                g.pending = false;
            }
            loop {
                if self.svc_stop.load(Ordering::Acquire) {
                    return;
                }
                live.clear();
                live.extend(self.sockets.lock().iter().filter_map(Weak::upgrade));
                let mut busy = false;
                for s in &live {
                    busy |= s.service();
                }
                live.clear();
                if !busy {
                    break;
                }
                sleep_step();
            }
        }
    }

    pub(crate) fn stop_service(&self) {
        let Some(handle) = self.thread.lock().take() else {
            return;
        };
        self.svc_stop.store(true, Ordering::Release);
        let deadline = Instant::now() + SERVICE_JOIN;
        let mut g = self.svc.lock();
        g.stop = true;
        self.svc_cv.notify_all();
        while !g.exited {
            if self.svc_cv.wait_until(&mut g, deadline).timed_out() {
                break;
            }
        }
        let exited = g.exited;
        drop(g);
        if exited {
            if handle.join().is_err() {
                tracing::error!(interface = %self.interface, state = "failed", reason = "panicked", "XDP service thread stopped");
            }
        } else {
            tracing::error!(
                interface = %self.interface,
                wait_ms = SERVICE_JOIN.as_millis(),
                reason = "join timed out",
                action = "leave running",
                "XDP service thread did not stop"
            );
        }
    }
}

fn affinity() -> String {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) } != 0 {
        return format!("unknown ({})", io::Error::last_os_error());
    }
    let cpus: Vec<String> = (0..libc::CPU_SETSIZE as usize)
        .filter(|i| unsafe { libc::CPU_ISSET(*i, &set) })
        .map(|i| i.to_string())
        .collect();
    cpus.join(",")
}

pub(crate) fn sleep_step() {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: SERVICE_STEP.as_nanos() as libc::c_long,
    };
    unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts, std::ptr::null_mut()) };
}

pub(crate) struct QueueParts {
    pub rx: RxImpl,
    pub tx: TxImpl,
    pub probe: ProbeImpl,
    pub device: String,
    pub queue: u32,
    pub mac: [u8; 6],
    /// Largest IP datagram (interface MTU, capped at frame size - 14).
    pub mtu: usize,
    pub primary_ip: Ipv4Addr,
}

impl QueueParts {
    pub(crate) fn into_core(self) -> (RxImpl, QueueCore) {
        let core = QueueCore {
            tx: Mutex::new(Some(self.tx)),
            probe: self.probe,
            rx_kick_pending: AtomicBool::new(false),
            tx_kick_pending: AtomicBool::new(false),
            tx_space: AtomicBool::new(true),
            waiters: Mutex::new(Vec::new()),
            waiter_count: AtomicUsize::new(0),
            retired: AtomicBool::new(false),
            gone: AtomicBool::new(false),
            device: self.device,
            queue: self.queue,
            mac: self.mac,
            mtu: self.mtu,
            primary_ip: self.primary_ip,
        };
        (self.rx, core)
    }
}

pub(crate) enum RxSource {
    Own(Vec<(usize, RxImpl)>),
    Inbox(Arc<Inbox>),
}

pub(crate) struct SocketParts {
    pub endpoint: &'static str,
    pub local: SocketAddrV4,
    pub xdp_ifindexes: Vec<u32>,
    /// Indexed by slave (device).
    pub queues: Arc<[QueueCore]>,
    pub rx: RxSource,
    pub kernel: KernelSock,
    pub routes: Arc<Routes>,
    pub peers: PeerTable,
    pub elig: Arc<Eligibility>,
}

pub(crate) struct QueueCore {
    tx: Mutex<Option<TxImpl>>,
    pub(crate) probe: ProbeImpl,
    pub(crate) rx_kick_pending: AtomicBool,
    tx_kick_pending: AtomicBool,
    tx_space: AtomicBool,
    waiters: Mutex<Vec<(u64, Waker)>>,
    waiter_count: AtomicUsize,
    retired: AtomicBool,
    pub(crate) gone: AtomicBool,
    pub(crate) device: String,
    pub(crate) queue: u32,
    mac: [u8; 6],
    mtu: usize,
    primary_ip: Ipv4Addr,
}

impl QueueCore {
    #[inline]
    fn waiting(&self) -> bool {
        self.waiter_count.load(Ordering::SeqCst) > 0
    }

    fn register_waiter(&self, id: u64, w: &Waker) {
        let mut g = self.waiters.lock();
        match g.iter_mut().find(|(i, _)| *i == id) {
            Some((_, old)) => {
                if !old.will_wake(w) {
                    *old = w.clone();
                }
            }
            None => g.push((id, w.clone())),
        }
        self.waiter_count.store(g.len(), Ordering::SeqCst);
    }

    fn wake_waiters(&self) {
        fence(Ordering::SeqCst);
        if self.waiter_count.load(Ordering::SeqCst) == 0 {
            return;
        }
        let mut g = self.waiters.lock();
        self.waiter_count.store(0, Ordering::SeqCst);
        for (_, w) in g.drain(..) {
            w.wake();
        }
    }

    fn forget(&self, id: u64) {
        let mut g = self.waiters.lock();
        g.retain(|(i, _)| *i != id);
        self.waiter_count.store(g.len(), Ordering::SeqCst);
    }

    pub(crate) fn retire(&self) {
        let first = !self.retired.swap(true, Ordering::SeqCst);
        let tx = self.tx.lock().take();
        drop(tx);
        self.clear_kicks();
        if first {
            self.probe.retire();
        }
        self.tx_space.store(true, Ordering::SeqCst);
        self.wake_waiters();
    }

    pub(crate) fn retired_placeholder(device: &str, queue: u32) -> Self {
        Self {
            tx: Mutex::new(None),
            probe: inert_probe(),
            rx_kick_pending: AtomicBool::new(false),
            tx_kick_pending: AtomicBool::new(false),
            tx_space: AtomicBool::new(true),
            waiters: Mutex::new(Vec::new()),
            waiter_count: AtomicUsize::new(0),
            retired: AtomicBool::new(true),
            gone: AtomicBool::new(false),
            device: device.to_string(),
            queue,
            mac: [0; 6],
            mtu: 0,
            primary_ip: Ipv4Addr::UNSPECIFIED,
        }
    }

    #[inline]
    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    fn clear_kicks(&self) {
        self.rx_kick_pending.store(false, Ordering::SeqCst);
        self.tx_kick_pending.store(false, Ordering::SeqCst);
    }
}

struct RxHalf {
    slave: usize,
    ring: RxImpl,
}

struct RxState {
    xdp_io: Vec<(usize, AsyncFd<FdRef>)>,
    kernel_io: Option<AsyncFd<FdRef>>,
    io_ready: bool,
    retired: bool,
    halves: Vec<RxHalf>,
    xdp_streak: u8,
}

const KERNEL_EVERY: u8 = 8;

struct FdRef(RawFd);

impl AsRawFd for FdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[allow(deprecated)]
fn register(fd: RawFd) -> io::Result<AsyncFd<FdRef>> {
    AsyncFd::with_interest(FdRef(fd), Interest::READABLE)
}

static NEXT_POLLER: AtomicU64 = AtomicU64::new(0);

pub struct XdpQuicSocket {
    hub: Arc<Hub>,
    rx: Mutex<RxState>,
    contender: WakerSlot,
    reader: Arc<WakerSlot>,
    inbox: Option<Arc<Inbox>>,
    queues: Arc<[QueueCore]>,
    queue_mask: u64,
    peers: PeerTable,
    elig: Arc<Eligibility>,
    routes: Arc<Routes>,
    xdp_ifindexes: Vec<u32>,
    kernel: KernelSock,
    last_bypass_log: AtomicU64,
    last_other_log: AtomicU64,
    last_other_tx_log: AtomicU64,
    last_kernel_busy_log: AtomicU64,
    last_kernel_failed_log: AtomicU64,
    bypass_logged: AtomicU64,
    other_logged: AtomicU64,
    other_tx_logged: AtomicU64,
    kernel_busy_logged: AtomicU64,
    kernel_failed_logged: AtomicU64,
    metrics: Metrics,
    endpoint: &'static str,
    local: SocketAddrV4,
    epoch: Instant,
}

impl fmt::Debug for XdpQuicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdpQuicSocket")
            .field("endpoint", &self.endpoint)
            .field("local", &self.local)
            .field("queues", &self.queues.len())
            .field("shared", &self.inbox.is_some())
            .finish_non_exhaustive()
    }
}

#[inline]
const fn usable_bit(mask: u64, i: usize) -> bool {
    i < 64 && mask & (1u64 << i) != 0
}

#[inline]
fn mark_space(q: &QueueCore) -> bool {
    if q.tx_space.load(Ordering::Relaxed) {
        return false;
    }
    q.tx_space.store(true, Ordering::SeqCst);
    true
}

impl XdpQuicSocket {
    pub(crate) fn new(hub: Arc<Hub>, p: SocketParts) -> Arc<Self> {
        let (halves, inbox) = match p.rx {
            RxSource::Own(h) => (
                h.into_iter()
                    .map(|(slave, ring)| RxHalf { slave, ring })
                    .collect(),
                None,
            ),
            RxSource::Inbox(i) => (Vec::new(), Some(i)),
        };
        let reader = inbox
            .as_ref()
            .map_or_else(|| Arc::new(WakerSlot::new()), |i| Arc::clone(&i.waker));
        let n = p.queues.len();
        let queue_mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        let s = Arc::new(Self {
            hub: Arc::clone(&hub),
            rx: Mutex::new(RxState {
                xdp_io: Vec::new(),
                kernel_io: None,
                io_ready: false,
                retired: false,
                halves,
                xdp_streak: 0,
            }),
            contender: WakerSlot::new(),
            reader,
            inbox,
            queues: p.queues,
            queue_mask,
            peers: p.peers,
            elig: p.elig,
            routes: p.routes,
            xdp_ifindexes: p.xdp_ifindexes,
            kernel: p.kernel,
            last_bypass_log: AtomicU64::new(0),
            last_other_log: AtomicU64::new(0),
            last_other_tx_log: AtomicU64::new(0),
            last_kernel_busy_log: AtomicU64::new(0),
            last_kernel_failed_log: AtomicU64::new(0),
            bypass_logged: AtomicU64::new(0),
            other_logged: AtomicU64::new(0),
            other_tx_logged: AtomicU64::new(0),
            kernel_busy_logged: AtomicU64::new(0),
            kernel_failed_logged: AtomicU64::new(0),
            metrics: Metrics::default(),
            endpoint: p.endpoint,
            local: p.local,
            epoch: Instant::now(),
        });
        hub.register(&s);
        s
    }

    /// Dedicated: ring work or kick owed. Shared: inbox non-empty. Both: kick or waiters pending.
    pub fn needs_service(&self) -> bool {
        let tx = |q: &QueueCore| {
            q.tx_kick_pending.load(Ordering::Relaxed)
                || (q.waiting() && q.probe.completions_pending())
        };
        match &self.inbox {
            None => self.queues.iter().any(|q| {
                q.probe.rx_pending()
                    || q.probe.fill_wants_wakeup()
                    || q.rx_kick_pending.load(Ordering::Relaxed)
                    || tx(q)
            }),
            Some(inbox) => !inbox.is_empty() || self.queues.iter().any(tx),
        }
    }

    pub fn wake(&self) {
        self.reader.wake();
        for q in self.queues.iter() {
            if q.waiting() && (q.tx_space.load(Ordering::SeqCst) || q.probe.completions_pending()) {
                q.wake_waiters();
            }
        }
    }

    pub fn metrics(&self) -> SocketMetrics {
        let mut m = self.metrics.snapshot();
        m.route_refresh_errors = self.routes.refresh_errors();
        if let Some(inbox) = &self.inbox {
            m.rx_dropped.0[DropReason::InboxFull.index()] += inbox.full_drops();
        }
        m
    }

    fn wake_waiters(&self) {
        for q in self.queues.iter() {
            q.wake_waiters();
        }
    }

    fn retire(&self) {
        {
            let mut st = self.rx.lock();
            st.xdp_io.clear();
            st.kernel_io = None;
            st.halves.clear();
            st.io_ready = true;
            st.retired = true;
        }
        self.contender.wake();
        if let Some(inbox) = &self.inbox {
            inbox.close();
        }
        for q in self.queues.iter() {
            q.retire();
        }
        if let Err(e) = self.kernel.retire() {
            tracing::warn!(
                interface = %self.hub.interface,
                endpoint = %self.endpoint,
                operation = "close_kernel_socket",
                error = %e,
                leftover = "socket stays open",
                action = "close on drop",
                "XDP kernel socket close failed"
            );
        }
        self.reader.wake();
    }

    fn retire_slave(&self, slave: usize) {
        let (io, half) = {
            let mut st = self.rx.lock();
            let io = st
                .xdp_io
                .iter()
                .position(|(s, _)| *s == slave)
                .map(|p| st.xdp_io.remove(p));
            let half = st
                .halves
                .iter()
                .position(|h| h.slave == slave)
                .map(|p| st.halves.remove(p));
            (io, half)
        };
        self.contender.wake();
        drop(io);
        drop(half);
        if let Some(q) = self.queues.get(slave) {
            q.retire();
        }
        self.reader.wake();
    }

    /// Per AF_XDP socket; never call on the packet path.
    pub fn xdp_statistics(&self) -> io::Result<XdpStatistics> {
        Ok(XdpStatistics::sum(&self.xdp_statistics_per_queue()?))
    }

    pub(crate) fn xdp_statistics_per_queue(&self) -> io::Result<Vec<libc::xdp_statistics>> {
        let mut out = Vec::with_capacity(self.queues.len());
        for q in self.queues.iter() {
            let g = q.tx.lock();
            if g.is_none() {
                continue;
            }
            let r = rings::xdp_statistics(q.probe.fd());
            drop(g);
            out.push(r?);
        }
        if out.is_empty() {
            self.hub.check()?;
        }
        Ok(out)
    }

    fn poll_recv_impl(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.hub.check() {
            return Poll::Ready(Err(e));
        }
        let mut guard = match self.rx.try_lock() {
            Some(g) => g,
            None => {
                self.contender.register(cx.waker());
                fence(Ordering::SeqCst);
                match self.rx.try_lock() {
                    Some(g) => g,
                    None => {
                        return Poll::Pending;
                    }
                }
            }
        };
        let r = self.recv_locked(&mut guard, cx, bufs, meta);
        drop(guard);
        self.contender.wake();
        r
    }

    fn recv_locked(
        &self,
        st: &mut RxState,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if !st.io_ready
            && let Err(e) = self.register_io(st)
        {
            return Poll::Ready(Err(e));
        }
        if st.retired {
            return Poll::Ready(Err(self.hub.down_error()));
        }
        if let Some(inbox) = &self.inbox {
            return self.recv_inbox(inbox, st, cx, bufs, meta);
        }
        let max = bufs.len().min(meta.len());
        let due = st.xdp_streak >= KERNEL_EVERY - 1;
        let xdp_max = if due { max.saturating_sub(1) } else { max };
        for _ in 0..2 {
            let (mut n, mut spent) = match self.drain_xdp(st, bufs, meta, xdp_max) {
                Ok(r) => r,
                Err(e) => return Poll::Ready(Err(e)),
            };
            self.reclaim_unlocked();
            if n > 0 && !due {
                st.xdp_streak += 1;
                return Poll::Ready(Ok(n));
            }
            let drain = n < max && (!spent || due);
            if drain {
                st.xdp_streak = 0;
                match self.drain_kernel(st, cx, &mut bufs[n..max], &mut meta[n..max]) {
                    Ok((k, s)) => {
                        n += k;
                        spent |= s;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            if spent {
                if !drain {
                    st.xdp_streak += 1;
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.reader.register(cx.waker());
            fence(Ordering::SeqCst);
            let mut again = false;
            for (i, io) in &st.xdp_io {
                let i = *i;
                match io.poll_read_ready(cx) {
                    Poll::Ready(Ok(mut g)) => {
                        if self.queues.get(i).is_some_and(|q| q.probe.rx_pending()) {
                            again = true;
                        } else {
                            g.clear_ready();
                            if io.poll_read_ready(cx).is_ready() {
                                again = true;
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(self.fatal_cause(format!(
                            "endpoint {}: polling an AF_XDP socket failed: {e}",
                            self.endpoint
                        ))));
                    }
                    Poll::Pending => {}
                }
            }
            again |= self.queues.iter().any(|q| q.probe.rx_pending());
            if !again {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn recv_inbox(
        &self,
        inbox: &Inbox,
        st: &mut RxState,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let max = bufs.len().min(meta.len());
        for _ in 0..2 {
            let (mut n, mut spent) = self.drain_inbox(inbox, bufs, meta, max);
            self.reclaim_unlocked();
            if n < max && !spent {
                match self.drain_kernel(st, cx, &mut bufs[n..max], &mut meta[n..max]) {
                    Ok((k, s)) => {
                        n += k;
                        spent |= s;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            if spent {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.reader.register(cx.waker());
            fence(Ordering::SeqCst);
            if inbox.is_empty() {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn drain_inbox(
        &self,
        inbox: &Inbox,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        max: usize,
    ) -> (usize, bool) {
        let mut n = 0;
        let mut used = 0;
        while used < max {
            let Some((m, payload)) = inbox.pop() else {
                break;
            };
            used += 1;
            let l = payload.len();
            match bufs[n].get_mut(..l) {
                Some(buf) => {
                    buf.copy_from_slice(&payload);
                    meta[n] = RecvMeta {
                        addr: SocketAddr::V4(m.src),
                        len: l,
                        stride: l,
                        ecn: None,
                        dst_ip: Some(IpAddr::V4(m.dst)),
                    };
                    self.peers.learn(
                        m.src,
                        PeerPath::Xdp {
                            mac: m.src_mac,
                            slave: m.slave,
                        },
                    );
                    n += 1;
                }
                None => self.metrics.rx_drop(DropReason::RxBufferTooSmall),
            }
        }
        if n > 0 {
            self.metrics.rx_xdp(n as u64);
        }
        (n, used >= max && n < max)
    }

    #[cold]
    fn register_io(&self, st: &mut RxState) -> io::Result<()> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(format!(
                "XDP socket {}: polled outside a tokio runtime; run the quinn endpoint on tokio with IO enabled",
                self.endpoint
            )));
        }
        let mut xdp = Vec::with_capacity(st.halves.len());
        for h in &st.halves {
            let Some(q) = self.queues.get(h.slave) else {
                continue;
            };
            let fd = q.probe.fd();
            if fd >= 0 {
                xdp.push((h.slave, register(fd)?));
            }
        }
        st.kernel_io = Some(register(self.kernel.fd())?);
        st.xdp_io = xdp;
        st.io_ready = true;
        Ok(())
    }

    #[inline]
    fn drain_xdp(
        &self,
        st: &mut RxState,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        max: usize,
    ) -> io::Result<(usize, bool)> {
        let mut n = 0;
        let mut used = 0;
        for h in st.halves.iter_mut() {
            let (i, half) = (h.slave, &mut h.ring);
            let Some(q) = self.queues.get(i) else {
                continue;
            };
            while used < max {
                let Some((f, len)) = half.pop() else { break };
                used += 1;
                match half
                    .frame(f)
                    .get(..len)
                    .ok_or(DropReason::Malformed)
                    .and_then(frame::parse)
                {
                    Ok(d) => {
                        let l = d.payload.len();
                        match bufs[n].get_mut(..l) {
                            Some(buf) => {
                                buf.copy_from_slice(d.payload);
                                meta[n] = RecvMeta {
                                    addr: SocketAddr::V4(d.src),
                                    len: l,
                                    stride: l,
                                    ecn: None,
                                    dst_ip: Some(IpAddr::V4(*d.dst.ip())),
                                };
                                self.peers.learn(
                                    d.src,
                                    PeerPath::Xdp {
                                        mac: d.src_mac,
                                        slave: i as u8,
                                    },
                                );
                                n += 1;
                            }
                            None => self.metrics.rx_drop(DropReason::RxBufferTooSmall),
                        }
                    }
                    Err(r) => self.metrics.rx_drop(r),
                }
                half.release(f);
            }
            half.refill();
            let owed = q.rx_kick_pending.load(Ordering::Relaxed)
                && q.rx_kick_pending.swap(false, Ordering::AcqRel);
            if (owed || half.fill_needs_wakeup()) && !q.gone.load(Ordering::Relaxed) {
                self.kick_rx(i, &*half)?;
            }
        }
        if n > 0 {
            self.metrics.rx_xdp(n as u64);
        }
        Ok((n, used >= max && n < max))
    }

    fn kick_rx(&self, i: usize, half: &(impl RxRing + ?Sized)) -> io::Result<()> {
        match half.wake() {
            Ok(()) => Ok(()),
            Err(e) => match classify_wake_error(&e) {
                WakeOutcome::Retry => {
                    self.queues[i]
                        .rx_kick_pending
                        .store(true, Ordering::Release);
                    self.hub.signal();
                    Ok(())
                }
                WakeOutcome::LinkDown => {
                    self.metrics.rx_drop(DropReason::LinkDown);
                    Ok(())
                }
                WakeOutcome::Gone if self.queues.len() > 1 => {
                    self.slave_gone(i);
                    self.metrics.rx_drop(DropReason::LinkDown);
                    Ok(())
                }
                WakeOutcome::Gone | WakeOutcome::Fatal => Err(self.fatal(i, "receive", &e)),
            },
        }
    }

    fn drain_kernel(
        &self,
        st: &mut RxState,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<(usize, bool)> {
        let Some(io) = st.kernel_io.as_ref() else {
            return Ok((0, false));
        };
        let budget = bufs.len();
        let mut n = 0;
        let mut used = 0;
        while used < budget {
            let mut guard = match io.poll_read_ready(cx) {
                Poll::Pending => return Ok((n, false)),
                Poll::Ready(Err(e)) => {
                    return Err(self.fatal_cause(format!(
                        "endpoint {}: polling the kernel UDP socket failed: {e}",
                        self.endpoint
                    )));
                }
                Poll::Ready(Ok(g)) => g,
            };
            let r = match self.kernel.recv(&mut bufs[n]) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNREFUSED)) => {
                    used += 1;
                    continue;
                }
                Err(e) => {
                    return Err(self.fatal_cause(format!(
                        "endpoint {}: receiving on the kernel UDP socket failed: {e} ({})",
                        self.endpoint,
                        rings::errno_name(&e)
                    )));
                }
            };
            used += 1;
            if !self.routes.is_same_host_rx(r.ifindex, *r.src.ip()) {
                let ours = self.xdp_ifindexes.contains(&r.ifindex);
                self.metrics.rx_drop(if ours {
                    DropReason::Bypass
                } else {
                    DropReason::OtherInterface
                });
                self.log_foreign(r, ours);
                continue;
            }
            if r.truncated {
                self.metrics.rx_drop(DropReason::RxBufferTooSmall);
                continue;
            }
            meta[n] = RecvMeta {
                addr: SocketAddr::V4(r.src),
                len: r.len,
                stride: r.len,
                ecn: None,
                dst_ip: Some(IpAddr::V4(r.dst)),
            };
            self.peers.learn(r.src, PeerPath::Kernel);
            self.metrics.kernel_served();
            n += 1;
        }
        Ok((n, n < budget))
    }

    #[cold]
    fn log_foreign(&self, r: crate::quic::kernel_sock::Received, ours: bool) {
        if ours {
            if rate_limited(&self.last_bypass_log, self.epoch) {
                let dropped_count = dropped_since(
                    &self.bypass_logged,
                    self.metrics.rx_dropped_of(DropReason::Bypass),
                );
                tracing::warn!(
                    interface = %self.hub.interface,
                    endpoint = %self.endpoint,
                    direction = "rx",
                    peer = %r.src,
                    ifindex = r.ifindex,
                    outcome = "dropped",
                    reason = DropReason::Bypass.name(),
                    dropped_count,
                    "XDP socket datagrams dropped"
                );
            }
        } else if rate_limited(&self.last_other_log, self.epoch) {
            let dropped_count = dropped_since(
                &self.other_logged,
                self.metrics.rx_dropped_of(DropReason::OtherInterface),
            );
            tracing::warn!(
                interface = %self.hub.interface,
                endpoint = %self.endpoint,
                direction = "rx",
                peer = %r.src,
                ifindex = r.ifindex,
                outcome = "dropped",
                reason = DropReason::OtherInterface.name(),
                dropped_count,
                "XDP socket datagrams dropped"
            );
        }
    }

    fn reclaim_unlocked(&self) {
        for q in self.queues.iter() {
            if !q.probe.completions_pending() {
                continue;
            }
            let woke = match q.tx.try_lock() {
                Some(mut g) => {
                    g.as_mut().is_some_and(|tx| tx.reclaim(RECLAIM_BATCH) > 0) && mark_space(q)
                }
                None => false,
            };
            if woke {
                q.wake_waiters();
            }
        }
    }

    fn try_send_impl(&self, t: &Transmit<'_>) -> io::Result<()> {
        self.hub.check()?;
        let SocketAddr::V4(dst) = t.destination else {
            self.metrics.tx_drop(DropReason::NoNextHop);
            return Ok(());
        };
        let src = match t.src_ip {
            Some(IpAddr::V4(ip)) if !ip.is_unspecified() => Some(ip),
            _ => None,
        };
        match self.peers.lookup_hashed(dst) {
            (Some(PeerPath::Kernel), _) => self.send_kernel(dst, src, t.contents),
            (Some(PeerPath::Xdp { mac, slave }), hash) => {
                self.send_xdp(dst, src, mac, Some(slave), hash, t.contents)
            }
            (None, hash) => self.send_routed(dst, src, hash, t.contents),
        }
    }

    #[cold]
    fn send_routed(
        &self,
        dst: SocketAddrV4,
        src: Option<Ipv4Addr>,
        hash: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        match self.routes.resolve(*dst.ip()) {
            Resolved::Xdp {
                mac,
                hop,
                ifindex,
                refresh,
            } => {
                if refresh {
                    self.routes.mark_used(ifindex, hop);
                }
                self.send_xdp(dst, src, mac, None, hash, payload)
            }
            Resolved::Kernel => self.send_kernel(dst, src, payload),
            Resolved::Other { .. } => {
                self.metrics.tx_drop(DropReason::OtherInterface);
                self.log_other_tx(dst);
                Ok(())
            }
            Resolved::Unresolved { hop } => {
                if let Some((h, ifindex)) = hop {
                    self.routes.mark_used(ifindex, h);
                }
                self.metrics.tx_drop(DropReason::NoNextHop);
                Ok(())
            }
            Resolved::Multipath { .. } => {
                self.metrics.tx_drop(DropReason::NoNextHop);
                Ok(())
            }
        }
    }

    #[cold]
    fn log_other_tx(&self, dst: SocketAddrV4) {
        if rate_limited(&self.last_other_tx_log, self.epoch) {
            let via = match self.routes.next_hop(*dst.ip()) {
                crate::monitor::NextHop::OtherInterface { name } => name,
                crate::monitor::NextHop::Xdp { .. } => "xdp".into(),
                crate::monitor::NextHop::Kernel => "kernel".into(),
                crate::monitor::NextHop::Unresolved => "none".into(),
                crate::monitor::NextHop::Multipath => "multipath".into(),
            };
            let dropped_count = dropped_since(
                &self.other_tx_logged,
                self.metrics.tx_dropped_of(DropReason::OtherInterface),
            );
            tracing::warn!(
                interface = %self.hub.interface,
                endpoint = %self.endpoint,
                direction = "tx",
                peer = %dst,
                routed_via = %via,
                outcome = "dropped",
                reason = DropReason::OtherInterface.name(),
                dropped_count,
                "XDP socket datagrams dropped"
            );
        }
    }

    pub(crate) fn send_probe(&self, to: SocketAddrV4) -> io::Result<()> {
        self.hub.check()?;
        self.kernel.send(to, None, &[])
    }

    pub(crate) fn tx_queues(&self) -> &[QueueCore] {
        &self.queues
    }

    fn listen_ip(&self) -> Option<Ipv4Addr> {
        let ip = *self.local.ip();
        (!ip.is_unspecified()).then_some(ip)
    }

    #[inline]
    fn send_xdp(
        &self,
        dst: SocketAddrV4,
        src: Option<Ipv4Addr>,
        mac: [u8; 6],
        learned: Option<u8>,
        hash: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        let mask = self.elig.mask() & self.queue_mask;
        let Some(qi) = pick_slave(mask, learned, hash).map(usize::from) else {
            self.metrics.tx_drop(DropReason::NoEligibleSlave);
            return Ok(());
        };
        let Some(q) = self.queues.get(qi) else {
            self.metrics.tx_drop(DropReason::NoEligibleSlave);
            return Ok(());
        };
        if payload.len() + (HEADERS - 14) > q.mtu {
            self.metrics.tx_drop(DropReason::Oversize);
            return Ok(());
        }
        let src_ip = src.or_else(|| self.listen_ip()).unwrap_or(q.primary_ip);
        let hdr = TxHeader {
            src_mac: q.mac,
            dst_mac: mac,
            src: SocketAddrV4::new(src_ip, self.local.port()),
            dst,
        };
        let mut g = q.tx.lock();
        let Some(tx) = g.as_mut() else {
            drop(g);
            return self.retired_queue();
        };
        let woke = tx.reclaim(RECLAIM_BATCH) > 0 && mark_space(q);
        let Some(f) = tx.reserve() else {
            q.tx_space.store(false, Ordering::SeqCst);
            self.metrics.tx_ring_full();
            drop(g);
            if woke {
                q.wake_waiters();
            }
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let len = match frame::build(tx.frame_mut(f), &hdr, payload, q.mtu) {
            Ok(len) => len,
            Err(_) => {
                drop(g);
                return Err(self.fatal_cause(format!(
                    "{} queue {}: transmit frame {f} is shorter than the checked datagram (frame accounting is inconsistent)",
                    q.device, q.queue
                )));
            }
        };
        tx.submit(f, len);
        self.metrics.tx_xdp();
        let owed = q.tx_kick_pending.load(Ordering::Relaxed)
            && q.tx_kick_pending.swap(false, Ordering::AcqRel);
        let r = if owed || tx.needs_wakeup() {
            self.kick_tx(qi, &*tx)
        } else {
            Ok(())
        };
        drop(g);
        if woke {
            q.wake_waiters();
        }
        r
    }

    #[cold]
    fn retired_queue(&self) -> io::Result<()> {
        self.hub.check()?;
        self.metrics.tx_drop(DropReason::NoEligibleSlave);
        Ok(())
    }

    fn kick_tx(&self, i: usize, tx: &(impl TxRing + ?Sized)) -> io::Result<()> {
        match tx.wake() {
            Ok(()) => Ok(()),
            Err(e) => match classify_wake_error(&e) {
                WakeOutcome::Retry => {
                    self.queues[i]
                        .tx_kick_pending
                        .store(true, Ordering::Release);
                    self.hub.signal();
                    Ok(())
                }
                WakeOutcome::LinkDown => {
                    self.metrics.tx_drop(DropReason::LinkDown);
                    Ok(())
                }
                WakeOutcome::Gone if self.queues.len() > 1 => {
                    self.slave_gone(i);
                    self.metrics.tx_drop(DropReason::LinkDown);
                    Ok(())
                }
                WakeOutcome::Gone | WakeOutcome::Fatal => Err(self.fatal(i, "transmit", &e)),
            },
        }
    }

    #[cold]
    fn slave_gone(&self, i: usize) {
        if let Some(q) = self.queues.get(i) {
            q.gone.store(true, Ordering::SeqCst);
            q.clear_kicks();
        }
    }

    fn send_kernel(
        &self,
        dst: SocketAddrV4,
        src: Option<Ipv4Addr>,
        payload: &[u8],
    ) -> io::Result<()> {
        let Err(e) = self.kernel.send(dst, src, payload) else {
            self.metrics.kernel_sent();
            return Ok(());
        };
        self.hub.check()?;
        let reason = match e.raw_os_error() {
            Some(libc::EAGAIN | libc::ENOBUFS) => DropReason::KernelBusy,
            Some(libc::EMSGSIZE) => DropReason::Oversize,
            Some(libc::ENETUNREACH | libc::EHOSTUNREACH) => DropReason::NoNextHop,
            Some(libc::ENETDOWN) => DropReason::LinkDown,
            Some(libc::EBADF | libc::ENOTSOCK | libc::EFAULT | libc::EINVAL) => {
                return Err(self.fatal_cause(format!(
                    "endpoint {}: the kernel UDP socket is unusable: {e} ({})",
                    self.endpoint,
                    rings::errno_name(&e)
                )));
            }
            _ => DropReason::KernelSendFailed,
        };
        self.metrics.tx_drop(reason);
        if matches!(
            reason,
            DropReason::KernelBusy | DropReason::KernelSendFailed
        ) {
            self.log_kernel_send(dst, reason, &e);
        }
        Ok(())
    }

    #[cold]
    fn log_kernel_send(&self, dst: SocketAddrV4, reason: DropReason, e: &io::Error) {
        let (last, logged) = match reason {
            DropReason::KernelBusy => (&self.last_kernel_busy_log, &self.kernel_busy_logged),
            _ => (&self.last_kernel_failed_log, &self.kernel_failed_logged),
        };
        if rate_limited(last, self.epoch) {
            let dropped_count = dropped_since(logged, self.metrics.tx_dropped_of(reason));
            tracing::warn!(
                interface = %self.hub.interface,
                endpoint = %self.endpoint,
                direction = "tx",
                peer = %dst,
                operation = "kernel_send",
                error = %e,
                outcome = "dropped",
                reason = reason.name(),
                dropped_count,
                "XDP socket datagrams dropped"
            );
        }
    }

    #[cold]
    fn fatal(&self, i: usize, dir: &str, e: &io::Error) -> io::Error {
        let q = &self.queues[i];
        self.fatal_cause(format!(
            "{} queue {}: AF_XDP {dir} wake-up failed: {e} ({})",
            q.device,
            q.queue,
            rings::errno_name(e)
        ))
    }

    #[cold]
    fn fatal_cause(&self, cause: String) -> io::Error {
        self.hub.fail(cause);
        self.hub.down_error()
    }

    #[inline]
    fn usable(&self) -> u64 {
        if self.queues.len() == 1 {
            1
        } else {
            self.elig.mask() & self.queue_mask
        }
    }

    fn writable_in(&self, mask: u64) -> bool {
        self.queues
            .iter()
            .enumerate()
            .all(|(i, q)| !usable_bit(mask, i) || q.tx_space.load(Ordering::SeqCst))
    }

    #[inline]
    fn writable_hint(&self) -> bool {
        match &*self.queues {
            [q] => q.tx_space.load(Ordering::SeqCst),
            _ => self.writable_in(self.usable()),
        }
    }

    fn poll_writable_impl(&self, id: u64, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.hub.check() {
            return Poll::Ready(Err(e));
        }
        if self.writable_hint() {
            return Poll::Ready(Ok(()));
        }
        let mut mask = self.usable();
        for (_, q) in self
            .queues
            .iter()
            .enumerate()
            .filter(|(i, _)| usable_bit(mask, *i))
        {
            let mut g = q.tx.lock();
            let Some(tx) = g.as_mut() else {
                drop(g);
                if let Err(e) = self.hub.check() {
                    return Poll::Ready(Err(e));
                }
                continue;
            };
            let woke = tx.reclaim(RECLAIM_BATCH) > 0 && mark_space(q);
            drop(g);
            if woke {
                q.wake_waiters();
            }
        }
        if self.writable_in(mask) {
            return Poll::Ready(Ok(()));
        }
        let mut registered = 0u64;
        for _ in 0..=self.queues.len() + 1 {
            let mut added = false;
            for (i, q) in self.queues.iter().enumerate() {
                if usable_bit(mask, i)
                    && registered & (1u64 << i) == 0
                    && !q.tx_space.load(Ordering::SeqCst)
                {
                    q.register_waiter(id, cx.waker());
                    registered |= 1u64 << i;
                    added = true;
                }
            }
            if added {
                self.hub.signal();
            }
            fence(Ordering::SeqCst);
            let now = self.usable();
            if now != mask {
                mask = now;
                continue;
            }
            match self
                .queues
                .iter()
                .enumerate()
                .find(|(i, q)| usable_bit(mask, *i) && !q.tx_space.load(Ordering::SeqCst))
            {
                None => return Poll::Ready(Ok(())),
                Some((i, _)) if registered & (1u64 << i) != 0 => return Poll::Pending,
                Some(_) => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn forget_poller(&self, id: u64) {
        for q in self.queues.iter() {
            q.forget(id);
        }
    }

    fn service(&self) -> bool {
        if self.hub.check().is_err() {
            return false;
        }
        let own_rx = self.inbox.is_none();
        let mut busy = false;
        for (i, q) in self.queues.iter().enumerate() {
            if q.tx_kick_pending.load(Ordering::Acquire) {
                match q.tx.try_lock() {
                    Some(mut g) => match g.as_mut() {
                        Some(tx) => {
                            if q.tx_kick_pending.swap(false, Ordering::AcqRel)
                                && self.kick_tx(i, &*tx).is_err()
                            {
                                return false;
                            }
                        }
                        None => q.tx_kick_pending.store(false, Ordering::Release),
                    },
                    None => busy = true,
                }
            }
            if own_rx && q.rx_kick_pending.load(Ordering::Acquire) {
                match self.rx.try_lock() {
                    Some(mut st) => {
                        let r = match st.halves.iter_mut().find(|h| h.slave == i) {
                            Some(h) if q.rx_kick_pending.swap(false, Ordering::AcqRel) => {
                                self.kick_rx(i, &h.ring)
                            }
                            Some(_) => Ok(()),
                            None => {
                                q.rx_kick_pending.store(false, Ordering::Release);
                                Ok(())
                            }
                        };
                        drop(st);
                        self.contender.wake();
                        if r.is_err() {
                            return false;
                        }
                    }
                    None => busy = true,
                }
            }
        }
        for q in self.queues.iter() {
            if !q.waiting() {
                continue;
            }
            match q.tx.try_lock() {
                Some(mut g) => {
                    if let Some(tx) = g.as_mut()
                        && tx.reclaim(RECLAIM_BATCH) > 0
                    {
                        mark_space(q);
                    }
                }
                None => busy = true,
            }
            if q.tx_space.load(Ordering::SeqCst) {
                q.wake_waiters();
            }
        }
        busy || self.queues.iter().any(|q| {
            q.waiting()
                || q.tx_kick_pending.load(Ordering::Acquire)
                || (own_rx && q.rx_kick_pending.load(Ordering::Acquire))
        })
    }
}

impl Drop for XdpQuicSocket {
    fn drop(&mut self) {
        if self.hub.check().is_err() {
            return;
        }
        let hook = self.hub.on_drop.lock().clone();
        if let Some(h) = hook {
            h(self.endpoint);
        }
    }
}

impl AsyncUdpSocket for XdpQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let id = NEXT_POLLER.fetch_add(1, Ordering::Relaxed);
        Box::pin(Poller { sock: self, id })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.try_send_impl(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv_impl(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::V4(self.local))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

struct Poller {
    sock: Arc<XdpQuicSocket>,
    id: u64,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdpPoller").field("id", &self.id).finish()
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sock.poll_writable_impl(self.id, cx)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        self.sock.forget_poller(self.id);
    }
}
