
use {
    crate::{
        classifier::owned_key,
        error::DropReason,
        metrics::{DropCounts, PumpMetrics},
        quic::{
            frame,
            rings::{RingProbe, RxRing, WakeOutcome, classify_wake_error, errno_name},
            socket::{Hub, QueueCore, RxImpl, WakerSlot, sleep_step},
        },
    },
    bytes::Bytes,
    crossbeam_queue::ArrayQueue,
    std::{
        io,
        net::{Ipv4Addr, SocketAddrV4},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread::JoinHandle,
        time::{Duration, Instant},
    },
};

pub(crate) const INBOX_CAPACITY: usize = 4096;
pub(crate) const PUMP_BATCH: usize = 64;
const POLL_TIMEOUT_MS: libc::c_int = 100;
const PUMP_JOIN: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RxMeta {
    pub src: SocketAddrV4,
    pub dst: Ipv4Addr,
    pub src_mac: [u8; 6],
    pub slave: u8,
}

pub(crate) struct Inbox {
    q: ArrayQueue<(RxMeta, Bytes)>,
    pub(crate) waker: Arc<WakerSlot>,
    full: AtomicU64,
    closed: AtomicBool,
}

impl Inbox {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            q: ArrayQueue::new(capacity),
            waker: Arc::new(WakerSlot::new()),
            full: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        })
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.q.is_empty() || self.closed.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn pop(&self) -> Option<(RxMeta, Bytes)> {
        self.q.pop()
    }

    pub(crate) fn full_drops(&self) -> u64 {
        self.full.load(Ordering::Relaxed)
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        while self.q.pop().is_some() {}
    }

    pub(crate) fn offer(&self, meta: RxMeta, payload: &[u8]) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        if self.q.is_full()
            || self
                .q
                .push((meta, Bytes::copy_from_slice(payload)))
                .is_err()
        {
            self.full.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum CoreRef {
    Tx(Arc<[QueueCore]>, usize),
    Own(QueueCore),
}

pub(crate) struct PumpQueue {
    rx: RxImpl,
    core: CoreRef,
    slave: u8,
}

impl PumpQueue {
    pub(crate) const fn own(rx: RxImpl, core: QueueCore, slave: u8) -> Self {
        Self {
            rx,
            core: CoreRef::Own(core),
            slave,
        }
    }

    pub(crate) fn tx(rx: RxImpl, tx: &Arc<[QueueCore]>, i: usize, slave: u8) -> Option<Self> {
        (i < tx.len()).then(|| Self {
            rx,
            core: CoreRef::Tx(Arc::clone(tx), i),
            slave,
        })
    }

    #[inline]
    fn core(&self) -> &QueueCore {
        match &self.core {
            CoreRef::Tx(a, i) => &a[*i],
            CoreRef::Own(c) => c,
        }
    }
}

#[derive(Default)]
struct Counters {
    delivered: AtomicU64,
    unknown: AtomicU64,
    dropped: [AtomicU64; DropReason::COUNT],
}

impl Counters {
    #[inline]
    fn count(&self, r: DropReason) {
        self.dropped[r.index()].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct Reader {
    hub: Arc<Hub>,
    queues: Vec<PumpQueue>,
    routes: Vec<(u64, usize)>,
    inboxes: Vec<Arc<Inbox>>,
    counters: Arc<Counters>,
    woken: Vec<bool>,
    retired: Option<Arc<AtomicU64>>,
    dropped: u64,
}

impl Reader {
    pub(crate) fn pass(&mut self) -> Result<bool, ()> {
        let Self {
            hub,
            queues,
            routes,
            inboxes,
            counters,
            woken,
            retired,
            ..
        } = self;
        let mut more = false;
        for pq in queues.iter_mut() {
            let mut used = 0;
            let mut delivered = 0;
            while used < PUMP_BATCH {
                let Some((f, len)) = pq.rx.pop() else { break };
                used += 1;
                match pq
                    .rx
                    .frame(f)
                    .get(..len)
                    .ok_or(DropReason::Malformed)
                    .and_then(frame::parse)
                {
                    Ok(d) => {
                        let key = owned_key(*d.dst.ip(), d.dst.port());
                        match routes.iter().find(|r| r.0 == key) {
                            Some(&(_, i)) => {
                                let m = RxMeta {
                                    src: d.src,
                                    dst: *d.dst.ip(),
                                    src_mac: d.src_mac,
                                    slave: pq.slave,
                                };
                                if inboxes[i].offer(m, d.payload) {
                                    woken[i] = true;
                                    delivered += 1;
                                }
                            }
                            None => {
                                counters.unknown.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(r) => counters.count(r),
                }
                pq.rx.release(f);
            }
            more |= used == PUMP_BATCH;
            if delivered > 0 {
                counters.delivered.fetch_add(delivered, Ordering::Relaxed);
            }
            for (i, w) in woken.iter_mut().enumerate() {
                if std::mem::take(w) {
                    inboxes[i].waker.wake();
                }
            }
            pq.rx.refill();
            let q = pq.core();
            let owed = q.rx_kick_pending.load(Ordering::Relaxed)
                && q.rx_kick_pending.swap(false, Ordering::AcqRel);
            let kicked = if (owed || pq.rx.fill_needs_wakeup()) && !q.gone.load(Ordering::Relaxed) {
                pq.rx.wake()
            } else {
                Ok(())
            };
            if let Err(e) = kicked {
                match classify_wake_error(&e) {
                    WakeOutcome::Retry => q.rx_kick_pending.store(true, Ordering::Release),
                    WakeOutcome::LinkDown => counters.count(DropReason::LinkDown),
                    WakeOutcome::Gone if retired.is_some() => {
                        q.gone.store(true, Ordering::SeqCst);
                        q.rx_kick_pending.store(false, Ordering::Release);
                        counters.count(DropReason::LinkDown);
                    }
                    WakeOutcome::Gone | WakeOutcome::Fatal => {
                        hub.fail(format!(
                            "{} queue {}: AF_XDP receive wake-up failed: {e} ({})",
                            q.device,
                            q.queue,
                            errno_name(&e)
                        ));
                        return Err(());
                    }
                }
            }
        }
        Ok(more)
    }

    pub(crate) fn drop_retired(&mut self) -> bool {
        let Some(r) = &self.retired else { return false };
        let bits = r.load(Ordering::Acquire);
        if bits == self.dropped {
            return false;
        }
        self.dropped = bits;
        let before = self.queues.len();
        self.queues
            .retain(|q| q.slave >= 64 || bits & (1u64 << q.slave) == 0);
        self.queues.len() != before
    }

    fn kick_owed(&self) -> bool {
        self.queues
            .iter()
            .any(|q| q.core().rx_kick_pending.load(Ordering::Relaxed))
    }

    fn run(mut self, stop: &AtomicBool) {
        unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0, 0, 0) };
        let pollfds = |queues: &[PumpQueue]| -> Vec<libc::pollfd> {
            queues
                .iter()
                .map(|q| libc::pollfd {
                    fd: q.core().probe.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect()
        };
        let mut fds = pollfds(&self.queues);
        loop {
            if stop.load(Ordering::Acquire) || self.hub.check().is_err() {
                return;
            }
            if self.drop_retired() {
                fds = pollfds(&self.queues);
            }
            match self.pass() {
                Err(()) => return,
                Ok(true) => continue,
                Ok(false) => {}
            }
            if self.kick_owed() {
                sleep_step();
                continue;
            }
            let rc =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN | libc::ENOMEM) => {
                        sleep_step();
                        continue;
                    }
                    _ => {
                        self.hub.fail(format!(
                            "XDP pump cannot wait on the AF_XDP sockets: {e} ({})",
                            errno_name(&e)
                        ));
                        return;
                    }
                }
            }
            if rc > 0
                && let Some((_, q)) = fds
                    .iter()
                    .zip(&self.queues)
                    .find(|(f, _)| f.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
            {
                self.hub.fail(format!(
                    "{} queue {}: the AF_XDP socket reports an error (poll)",
                    q.core().device,
                    q.core().queue
                ));
                return;
            }
        }
    }
}

pub(crate) struct Pump {
    inboxes: Vec<Arc<Inbox>>,
    tx: Arc<[QueueCore]>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    interface: String,
    retired: Option<Arc<AtomicU64>>,
}

impl Pump {
    pub(crate) fn new(
        hub: Arc<Hub>,
        queues: Vec<PumpQueue>,
        routes: &[(Ipv4Addr, u16, usize)],
        endpoints: usize,
        tx: Arc<[QueueCore]>,
    ) -> (Self, Reader) {
        let inboxes: Vec<Arc<Inbox>> = (0..endpoints).map(|_| Inbox::new(INBOX_CAPACITY)).collect();
        let counters = Arc::new(Counters::default());
        let routes = routes
            .iter()
            .filter(|r| r.2 < endpoints)
            .map(|(ip, port, i)| (owned_key(*ip, *port), *i))
            .collect();
        let retired = (tx.len() > 1).then(|| Arc::new(AtomicU64::new(0)));
        let reader = Reader {
            hub: Arc::clone(&hub),
            queues,
            routes,
            inboxes: inboxes.iter().map(Arc::clone).collect(),
            counters: Arc::clone(&counters),
            woken: vec![false; endpoints],
            retired: retired.as_ref().map(Arc::clone),
            dropped: 0,
        };
        let pump = Self {
            inboxes,
            tx,
            counters,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            interface: hub.interface.clone(),
            retired,
        };
        (pump, reader)
    }

    pub(crate) fn spawn(&mut self, reader: Reader) -> io::Result<()> {
        let stop = Arc::clone(&self.stop);
        let hub = Arc::clone(&reader.hub);
        let handle = std::thread::Builder::new().name("gun-xdp-pump".into()).spawn(move || {
            tracing::debug!(interface = %hub.interface, state = "ready", "XDP pump started");
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || reader.run(&stop)));
            if run.is_err() {
                hub.fail("XDP pump thread panicked".into());
            } else {
                let reason = if hub.failed().is_some() { "context failed" } else { "shutdown" };
                tracing::debug!(interface = %hub.interface, state = "stopped", reason, "XDP pump stopped");
            }
        })?;
        self.thread = Some(handle);
        Ok(())
    }

    pub(crate) fn inbox(&self, endpoint: usize) -> Option<Arc<Inbox>> {
        self.inboxes.get(endpoint).map(Arc::clone)
    }

    pub(crate) fn retire_slave(&self, slave: usize) {
        if let Some(r) = &self.retired
            && slave < 64
        {
            r.fetch_or(1u64 << slave, Ordering::AcqRel);
        }
        if let Some(q) = self.tx.get(slave) {
            q.retire();
        }
    }

    pub(crate) fn tx_queues(&self) -> Arc<[QueueCore]> {
        Arc::clone(&self.tx)
    }

    pub(crate) fn metrics(&self) -> PumpMetrics {
        let mut dropped = [0; DropReason::COUNT];
        for (o, c) in dropped.iter_mut().zip(&self.counters.dropped) {
            *o = c.load(Ordering::Relaxed);
        }
        PumpMetrics {
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            unknown_destination: self.counters.unknown.load(Ordering::Relaxed),
            rx_dropped: DropCounts(dropped),
        }
    }

    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.thread.take() {
            let deadline = Instant::now() + PUMP_JOIN;
            while !h.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            if h.is_finished() {
                if h.join().is_err() {
                    tracing::error!(interface = %self.interface, state = "failed", reason = "panicked", "XDP pump stopped");
                }
            } else {
                tracing::error!(
                    interface = %self.interface,
                    wait_ms = PUMP_JOIN.as_millis(),
                    reason = "join timed out",
                    action = "leave running",
                    leftover = "AF_XDP sockets open",
                    "XDP pump did not stop"
                );
                for i in &self.inboxes {
                    i.close();
                }
            }
        }
        for q in self.tx.iter() {
            q.retire();
        }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.stop();
    }
}
