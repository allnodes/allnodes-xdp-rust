
use {
    crate::{
        error::{XdpError, XdpFailure},
        metrics::PumpMetrics,
        settings::{EndpointSpec, XdpMode, XdpSettings},
    },
    std::{
        fmt,
        net::{SocketAddr, SocketAddrV4},
        sync::Arc,
    },
};

/// What the context runs on, for logs and metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdpSummary {
    pub interface: String,
    pub devices: Vec<String>,
    pub driver: String,
    pub mode: XdpMode,
    pub zero_copy: bool,
    pub bond: bool,
    /// "dedicated" or "shared".
    pub layout: &'static str,
    pub queues: Vec<(String, Vec<u32>)>,
    pub endpoints: Vec<(&'static str, SocketAddrV4)>,
}

impl XdpSummary {
    const fn mode_name(&self) -> &'static str {
        match self.mode {
            XdpMode::Drv => "drv",
            XdpMode::Skb => "skb",
        }
    }
}

#[cfg(target_os = "linux")]
impl XdpSummary {
    fn queues_field(&self) -> String {
        let per: Vec<String> = self
            .queues
            .iter()
            .map(|(dev, queues)| {
                let q: Vec<String> = queues.iter().map(u32::to_string).collect();
                format!("{dev}:{}", q.join(","))
            })
            .collect();
        per.join(";")
    }

    fn endpoints_field(&self) -> String {
        let all: Vec<String> = self
            .endpoints
            .iter()
            .map(|(name, addr)| format!("{name}={addr}"))
            .collect();
        all.join(",")
    }

    fn log_started(&self) {
        tracing::info!(
            interface = %self.interface,
            devices = %self.devices.join(","),
            driver = %self.driver,
            mode = self.mode_name(),
            zero_copy = self.zero_copy,
            bonded = self.bond,
            layout = self.layout,
            queues = %self.queues_field(),
            endpoints = %self.endpoints_field(),
            state = "ready",
            "XDP context started"
        );
    }
}

impl fmt::Display for XdpSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.mode_name();
        write!(
            f,
            "interface={} devices={} driver={} mode={mode} zero_copy={} bond={} steering={}",
            self.interface,
            self.devices.join(","),
            self.driver,
            self.zero_copy,
            self.bond,
            self.layout
        )?;
        for (dev, queues) in &self.queues {
            let q: Vec<String> = queues.iter().map(u32::to_string).collect();
            write!(f, " queues[{dev}]={}", q.join(","))?;
        }
        for (name, addr) in &self.endpoints {
            write!(f, " {name}={addr}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct FailureState {
    tx: tokio::sync::watch::Sender<Option<XdpFailure>>,
}

impl FailureState {
    pub(crate) fn new() -> Self {
        Self {
            tx: tokio::sync::watch::Sender::new(None),
        }
    }

    pub(crate) fn fail(&self, cause: String) -> bool {
        self.tx.send_if_modified(|v| {
            if v.is_some() {
                return false;
            }
            *v = Some(XdpFailure { cause });
            true
        })
    }

    pub(crate) fn get(&self) -> Option<XdpFailure> {
        self.tx.borrow().clone()
    }

    pub(crate) async fn wait(&self) -> XdpFailure {
        let mut rx = self.tx.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(v) => v.as_ref().cloned().unwrap_or_else(|| XdpFailure {
                cause: "woken without a cause (internal error)".into(),
            }),
            Err(_) => XdpFailure {
                cause: "the XDP context is gone".into(),
            },
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::XdpContext;
#[cfg(target_os = "linux")]
pub(crate) use linux::{SETUP_LOCK_WAIT, take_setup_lock};

#[cfg(target_os = "linux")]
mod linux {
    use {
        super::*,
        crate::{
            installer::{self, RuleCheck},
            quic::kernel_sock::KernelSock,
            monitor::{
                self, BondEvent, BondParts, BondState, DeviceObs, LockObs, Managed, Monitor,
                MonitorParts, Observation, Routes, Unread, read_retrying,
            },
            nic::EthtoolNic,
            quic::{
                peers::PeerTable,
                pump::{Pump, PumpQueue},
                rings,
                socket::{self, Hub, QueueCore, QueueParts, RxSource, SocketParts, XdpQuicSocket},
            },
            setup::{
                self, Build, Change, Journal, Plan, Resources, setup_err, with_rollback_errors,
            },
            slaves::{self, Eligibility, Ineligible, SysfsRoot},
            device::NetworkDevice,
            dispatcher::{self, BpffsLock, ChainState},
            netlink::{self, NetlinkSocket},
        },
        parking_lot::Mutex,
        std::{
            error::Error,
            io,
            net::{Ipv4Addr, UdpSocket},
            sync::atomic::{AtomicU64, Ordering},
            time::{Duration, Instant},
        },
    };

    const _: fn() = || {
        const fn shared<T: Send + Sync>() {}
        shared::<XdpContext>();
    };

    const _: fn(&XdpContext, SocketAddr) = |ctx, dest| {
        const fn send<T: Send>(_: &T) {}
        send(&ctx.prepare(dest));
    };

    struct Live {
        res: Resources,
        journal: Journal<Change>,
    }

    pub struct XdpContext {
        plan: Plan,
        summary: XdpSummary,
        live: Mutex<Option<Live>>,
        hub: Arc<Hub>,
        elig: Arc<Eligibility>,
        pump: Mutex<Option<Pump>>,
        routes: Arc<Routes>,
        monitor: Mutex<Option<Monitor>>,
        retired: AtomicU64,
        deferred: std::sync::atomic::AtomicBool,
        lock_warned: Mutex<Option<(Instant, Instant)>>,
    }

    enum Flock {
        Real(BpffsLock),
    }

    impl Flock {
        const fn held(&self) -> setup::Held<'_> {
            match self {
                Self::Real(l) => setup::Held::Flock(l),
            }
        }

        const fn real(&self) -> Option<&BpffsLock> {
            match self {
                Self::Real(l) => Some(l),
            }
        }
    }

    const LOCK_WARN_EVERY: Duration = Duration::from_secs(10);
    pub(crate) const SETUP_LOCK_WAIT: Duration = Duration::from_secs(30);
    pub(super) const TEARDOWN_LOCK_WAIT: Duration = Duration::from_secs(5);
    const LOCK_TRY_STEP: Duration = Duration::from_millis(10);

    fn wait_for_lock<L>(
        bound: Duration,
        mut try_once: impl FnMut() -> Result<Option<L>, String>,
    ) -> Result<Option<L>, String> {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(l) = try_once()? {
                return Ok(Some(l));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(LOCK_TRY_STEP.min(deadline - now));
        }
    }

    pub(crate) fn take_setup_lock<L>(
        interface: &str,
        bound: Duration,
        try_once: impl FnMut() -> Result<Option<L>, String>,
    ) -> Result<L, XdpError> {
        let path = monitor::BPFFS_LOCK_PATH;
        match wait_for_lock(bound, try_once) {
            Ok(Some(l)) => Ok(l),
            Ok(None) => Err(setup_err(
                interface,
                None,
                None,
                format!(
                    "cannot take the bpffs lock {path}: held by another process for {} s",
                    bound.as_secs()
                ),
                format!(
                    "find the holder with `fuser -v {path}` and stop it (or let it finish), then restart"
                ),
            )),
            Err(e) => Err(setup_err(
                interface,
                None,
                None,
                format!("cannot take the bpffs lock: {e}"),
                "mount a bpf filesystem at /sys/fs/bpf (`mount -t bpf bpf /sys/fs/bpf`)",
            )),
        }
    }

    struct HealthDev {
        name: String,
        ifindex: u32,
        member: u32,
    }

    struct IfaceFacts {
        ifindex: u32,
        mac: [u8; 6],
        mtu: usize,
        primary_ip: Ipv4Addr,
    }

    fn iface_facts(interface: &str, endpoint: Option<&str>) -> Result<IfaceFacts, XdpError> {
        let err = |what: String| {
            setup_err(
                interface,
                None,
                endpoint,
                what,
                "check the interface (`ip addr show`)",
            )
        };
        let dev = NetworkDevice::new(interface)
            .map_err(|e| err(format!("{interface} cannot be found: {e}")))?;
        let mac = dev
            .mac_addr()
            .map_err(|e| err(format!("cannot read the MAC address of {interface}: {e}")))?
            .0;
        let mtu = std::fs::read_to_string(format!("/sys/class/net/{interface}/mtu"))
            .map_err(|e| err(format!("cannot read the MTU of {interface}: {e}")))?
            .trim()
            .parse::<usize>()
            .map_err(|e| err(format!("unreadable MTU of {interface}: {e}")))?;
        let primary_ip = *netlink::ipv4_addrs(dev.if_index())
            .map_err(|e| {
                err(format!(
                    "cannot list the IPv4 addresses of {interface}: {e}"
                ))
            })?
            .first()
            .ok_or_else(|| err(format!("{interface} has no IPv4 address")))?;
        Ok(IfaceFacts {
            ifindex: dev.if_index(),
            mac,
            mtu: mtu.min(setup::FRAME_SIZE as usize - 14),
            primary_ip,
        })
    }

    impl XdpContext {
        /// Runs the setup transaction; on error nothing of ours is left.
        /// Threads inherit the caller's CPU affinity: do not build from a latency-pinned thread.
        pub fn new(
            settings: &XdpSettings,
            endpoints: &[EndpointSpec],
        ) -> Result<Arc<Self>, XdpError> {
            let interface = setup::interface_name(settings)?;
            let hub = Hub::new(&interface);
            hub.start_service().map_err(|e| {
                setup_err(
                    &interface,
                    None,
                    None,
                    format!("cannot start the XDP service thread: {e}"),
                    "check the process thread limit",
                )
            })?;
            let built = Self::build(settings, endpoints, interface, Arc::clone(&hub));
            if built.is_err() {
                hub.stop_service();
            }
            built
        }

        fn build(
            settings: &XdpSettings,
            endpoints: &[EndpointSpec],
            interface: String,
            hub: Arc<Hub>,
        ) -> Result<Arc<Self>, XdpError> {
            setup::check_settings(&interface, settings)?;
            setup::check_caps(&interface, &setup::missing_caps(&interface)?)?;
            let die_at = setup::die_at_from_env(&interface)?;
            BpffsLock::prepare_dir().map_err(|e| {
                setup_err(
                    &interface,
                    None,
                    None,
                    format!("cannot take the bpffs lock: {e}"),
                    "mount a bpf filesystem at /sys/fs/bpf (`mount -t bpf bpf /sys/fs/bpf`)",
                )
            })?;
            let lock = take_setup_lock(&interface, SETUP_LOCK_WAIT, || {
                BpffsLock::try_acquire().map_err(|e| e.to_string())
            })?;
            let nic = EthtoolNic;
            let prepared = setup::prepare(settings, endpoints, &interface, &nic, &lock)?;
            let plan = prepared.plan;
            let mut res = Resources::new(prepared.devices, &plan.endpoints).paced_for(&plan);
            let mut journal = Journal::new(die_at);
            {
                let mut b = Build {
                    nic: &nic,
                    lock: Some(&lock),
                    plan: &plan,
                    res: &mut res,
                };
                setup::run_steps(
                    &interface,
                    &mut b,
                    &mut journal,
                    &setup::steps(),
                    setup::undo,
                )?;
            }
            let pump = if plan.kind == setup::LayoutKind::Shared {
                match start_pump(&plan, &mut res, &hub) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        let errors =
                            setup::teardown(&nic, Some(&lock), &plan, &mut res, &mut journal);
                        return Err(with_rollback_errors(e, &interface, &errors));
                    }
                }
            } else {
                None
            };
            let watched = match watch_routes(&plan, &res) {
                Ok(w) => w,
                Err(e) => {
                    if let Some(mut p) = pump {
                        p.stop();
                    }
                    let errors = setup::teardown(&nic, Some(&lock), &plan, &mut res, &mut journal);
                    return Err(with_rollback_errors(e, &interface, &errors));
                }
            };
            drop(lock);
            let summary = summarize(&plan, &res.ports);
            summary.log_started();
            if plan.kind == setup::LayoutKind::Shared {
                tracing::warn!(
                    interface = %plan.interface,
                    layout = plan.kind.name(),
                    state = "degraded",
                    reason = "no ntuple filters",
                    "XDP steering layout is shared"
                );
            }
            let elig = Arc::new(Eligibility::new(device_mask(plan.devices.len())));
            let bond_state = plan.bond.then(|| first_eligibility(&plan, &elig));
            let Watched {
                routes,
                events,
                xdp,
                health,
            } = watched;
            let devices: Vec<(String, u32)> =
                health.iter().map(|d| (d.name.clone(), d.ifindex)).collect();
            let ctx = Arc::new(Self {
                plan,
                summary,
                live: Mutex::new(Some(Live { res, journal })),
                hub: Arc::clone(&hub),
                elig,
                pump: Mutex::new(pump),
                routes: Arc::clone(&routes),
                monitor: Mutex::new(None),
                retired: AtomicU64::new(0),
                deferred: std::sync::atomic::AtomicBool::new(false),
                lock_warned: Mutex::new(None),
            });
            Self::install_drop_hook(&ctx);
            let weak = Arc::downgrade(&ctx);
            let observe: monitor::Observe = Box::new(move |deadline| {
                let ctx = weak.upgrade()?;
                ctx.observe(&health, deadline)
            });
            let use_neighbor = monitor::kernel_use_neighbor();
            let bond = bond_state.map(|state| {
                let weak = Arc::downgrade(&ctx);
                let weak2 = Arc::downgrade(&ctx);
                BondParts {
                    name: ctx.plan.interface.clone(),
                    root: SysfsRoot::system(),
                    state,
                    elig: Arc::clone(&ctx.elig),
                    retire: Box::new(move |slave| {
                        if let Some(ctx) = weak.upgrade() {
                            ctx.retire_slave(slave);
                        }
                    }),
                    pending: Box::new(move || {
                        if let Some(ctx) = weak2.upgrade() {
                            ctx.leave_deferred();
                        }
                    }),
                }
            });
            let started = Monitor::start(MonitorParts {
                hub,
                routes,
                events,
                xdp,
                devices,
                observe,
                use_neighbor,
                bond,
            });
            match started {
                Ok(m) => *ctx.monitor.lock() = Some(m),
                Err(e) => {
                    return Err(setup_err(
                        &ctx.plan.interface,
                        None,
                        None,
                        format!("cannot start the XDP monitor thread: {e}"),
                        "check the process thread limit",
                    ));
                }
            }
            Ok(ctx)
        }

        /// Listen address with the actual port.
        pub fn local_addr(&self, endpoint: &str) -> Option<SocketAddrV4> {
            self.summary
                .endpoints
                .iter()
                .find(|(n, _)| *n == endpoint)
                .map(|(_, a)| *a)
        }

        pub fn summary(&self) -> XdpSummary {
            self.summary.clone()
        }

        pub fn failed(&self) -> Option<XdpFailure> {
            self.hub.failed()
        }

        pub async fn wait_failed(&self) -> XdpFailure {
            self.hub.wait_failed().await
        }

        /// Shared layout only; `None` otherwise or after shutdown.
        pub fn pump_metrics(&self) -> Option<PumpMetrics> {
            self.pump.lock().as_ref().map(Pump::metrics)
        }

        /// One bit per device in `summary().devices` order; a single device is always 1.
        pub fn eligible_slaves(&self) -> u64 {
            self.elig.mask()
        }

        /// One syscall per device: keep it off the packet path. Errors once shut down.
        pub fn no_socket_drops(&self) -> Result<u64, XdpError> {
            let retired = self.retired.load(Ordering::SeqCst);
            let guard = self.live.lock();
            let live = guard.as_ref().ok_or_else(|| self.shut_down_error(None))?;
            let mut total = 0u64;
            for (_, d) in live
                .res
                .devices
                .iter()
                .enumerate()
                .filter(|(i, d)| !d.retired && !is_bit(retired, *i))
            {
                let Some(cl) = d.classifier.as_ref() else {
                    continue;
                };
                let name = d.dev.name();
                let n = cl.no_socket_drops().map_err(|e| {
                    setup_err(
                        &self.plan.interface,
                        (name != self.plan.interface).then_some(name),
                        None,
                        format!("cannot read the classifier drop counter of {name}: {e}"),
                        "check the process capabilities (CAP_BPF, CAP_SYS_ADMIN)",
                    )
                })?;
                total = total.saturating_add(n);
            }
            Ok(total)
        }

        /// Resolves route and next hop to `dest` before a dial, off the hot path. IPv4 only.
        /// `Unreachable` if the route leaves another interface or the next hop stays unresolved.
        pub async fn prepare(&self, dest: SocketAddr) -> Result<(), XdpError> {
            if let Some(f) = self.hub.failed() {
                return Err(XdpError::Failed(f));
            }
            monitor::prepare(
                &self.routes,
                dest,
                |hop| self.send_probe(hop),
                monitor::PREPARE_TIMEOUT,
                self.hub.stopped(),
            )
            .await
        }

        fn send_probe(&self, hop: Ipv4Addr) -> io::Result<()> {
            let to = SocketAddrV4::new(hop, 9);
            if let Some(s) = self.hub.live_sockets().first() {
                return s.send_probe(to);
            }
            let s = UdpSocket::bind("0.0.0.0:0")?;
            s.set_nonblocking(true)?;
            s.send_to(&[], to).map(drop)
        }

        fn observe(&self, all: &[HealthDev], deadline: Instant) -> Option<Observation> {
            let abort = || self.hub.check().is_err();
            let retired = self.retired.load(Ordering::SeqCst);
            let active: Vec<usize> = (0..all.len()).filter(|i| !is_bit(retired, *i)).collect();
            let devs: Vec<&HealthDev> = active.iter().filter_map(|i| all.get(*i)).collect();
            let unread = |what: String, e: &dyn Error| Unread {
                what,
                error: e.to_string(),
            };
            let chain_what = |d: &HealthDev| format!("the XDP chain on {}", d.name);
            let gone_slave = |d: &HealthDev, r: Result<ChainState, Unread>| match r {
                Ok(ChainState::Detached)
                    if self.plan.bond && setup::interface_gone(d.ifindex).unwrap_or(false) =>
                {
                    Err(Unread {
                        what: chain_what(d),
                        error: format!("{} is gone (unregistered)", d.name),
                    })
                }
                other => other,
            };
            let (lock, chain): (_, Vec<_>) = match BpffsLock::try_acquire() {
                Ok(Some(l)) => {
                    let c = devs
                        .iter()
                        .map(|d| {
                            gone_slave(
                                d,
                                dispatcher::member_in_chain(d.ifindex, d.member, Some(&l))
                                    .map_err(|e| unread(chain_what(d), e.as_ref())),
                            )
                        })
                        .collect();
                    drop(l);
                    (Ok(LockObs::Held), c)
                }
                other => {
                    let lock = match other {
                        Ok(_) => Ok(LockObs::Busy),
                        Err(e) => Err(unread(
                            format!("the bpffs lock {}", monitor::BPFFS_LOCK_PATH),
                            e.as_ref(),
                        )),
                    };
                    let c = devs
                        .iter()
                        .map(|d| {
                            let r = read_retrying(deadline, &abort, || {
                                dispatcher::member_in_chain(d.ifindex, d.member, None)
                            })
                            .map_err(|e| unread(chain_what(d), e.as_ref()));
                            gone_slave(d, r)
                        })
                        .collect();
                    (lock, c)
                }
            };

            enum What {
                Drops,
                Xsk(u32, u32, String),
            }
            struct Item {
                dev: usize,
                what: What,
                result: Option<Result<Option<u64>, Box<dyn Error>>>,
            }
            let (names, rules, mut items, missing) = {
                let guard = self.live.lock();
                let live = guard.as_ref()?;
                let kept: Vec<(usize, &setup::DeviceRes)> = live
                    .res
                    .devices
                    .iter()
                    .enumerate()
                    .filter(|(i, d)| !d.retired && !is_bit(retired, *i))
                    .collect();
                let names: Vec<String> =
                    kept.iter().map(|(_, d)| d.dev.name().to_string()).collect();
                let rules: Vec<_> = kept
                    .iter()
                    .flat_map(|(_, d)| d.rules.iter().cloned())
                    .collect();
                let mut items = Vec::new();
                let mut missing = Vec::new();
                for (d, (_, dr)) in kept.iter().enumerate() {
                    let Some(cl) = dr.classifier.as_ref() else {
                        missing.push(d);
                        continue;
                    };
                    if !dr.drops_off {
                        items.push(Item {
                            dev: d,
                            what: What::Drops,
                            result: None,
                        });
                    }
                    for (slot, queue) in cl.registered() {
                        let label = socket_label(&self.plan, &names[d], slot, queue);
                        items.push(Item {
                            dev: d,
                            what: What::Xsk(slot, queue, label),
                            result: None,
                        });
                    }
                }
                (names, rules, items, missing)
            };
            loop {
                let mut pending = false;
                {
                    let mut guard = self.live.lock();
                    let live = guard.as_mut()?;
                    for it in items.iter_mut().filter(|it| {
                        it.result.as_ref().is_none_or(|r| {
                            r.as_ref().is_err_and(|e| monitor::is_transient(e.as_ref()))
                        })
                    }) {
                        let Some(cl) = active
                            .get(it.dev)
                            .and_then(|i| live.res.devices.get_mut(*i))
                            .and_then(|d| d.classifier.as_mut())
                        else {
                            it.result = Some(Err("the classifier is gone (internal error)".into()));
                            continue;
                        };
                        let r: Result<Option<u64>, Box<dyn Error>> = match &it.what {
                            What::Drops => cl.no_socket_drops().map(Some).map_err(Into::into),
                            What::Xsk(slot, queue, _) => cl
                                .xsk_in_map(*slot, *queue)
                                .map(|p| p.map(u64::from))
                                .map_err(Into::into),
                        };
                        pending |= r.as_ref().is_err_and(|e| monitor::is_transient(e.as_ref()));
                        it.result = Some(r);
                    }
                }
                if !pending || Instant::now() >= deadline || abort() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut devices: Vec<DeviceObs> = names
                .iter()
                .zip(chain)
                .map(|(name, chain)| DeviceObs {
                    name: name.clone(),
                    chain,
                    drops: Ok(None),
                })
                .collect();
            for d in missing {
                let name = &names[d];
                devices[d].drops = Err(Unread {
                    what: format!("the classifier of {name}"),
                    error: "not loaded (internal error)".into(),
                });
            }
            let mut sockets = Vec::new();
            for it in items {
                let name = &names[it.dev];
                match (it.what, it.result) {
                    (What::Drops, Some(r)) => {
                        devices[it.dev].drops = r.map_err(|e| {
                            unread(format!("the classifier drop counter of {name}"), e.as_ref())
                        });
                    }
                    (What::Xsk(_, _, label), Some(Ok(None))) => drop(label),
                    (What::Xsk(_, _, label), Some(r)) => {
                        let present = r
                            .map(|p| p == Some(1))
                            .map_err(|e| unread(format!("the XSKS entry of {label}"), e.as_ref()));
                        sockets.push((label, present));
                    }
                    (_, None) => {}
                }
            }
            let mut unreadable = None;
            let checked = read_retrying(deadline, &abort, || {
                match installer::verify_classified(&EthtoolNic, &rules) {
                    Ok(()) => Ok(Ok(())),
                    Err(RuleCheck::Breach(e)) => Ok(Err(e.to_string())),
                    Err(RuleCheck::Unreadable { device, error }) => {
                        unreadable = Some(device);
                        Err(Box::new(error) as Box<dyn Error>)
                    }
                }
            });
            let rules = checked.map_err(|e| {
                unread(
                    format!(
                        "the steering rules of {}",
                        unreadable.as_deref().unwrap_or("the devices")
                    ),
                    e.as_ref(),
                )
            });
            Some(Observation {
                now: Instant::now(),
                lock,
                devices,
                sockets,
                rules,
                tx: self.hub.tx_progress(),
                carrier: Vec::new(),
                routing: Ok(()),
                bond: Vec::new(),
                ineligible: Vec::new(),
            })
        }

        fn endpoint_dropped(&self, endpoint: &str) {
            let Ok(i) = self.endpoint_index(endpoint) else {
                return;
            };
            let mut guard = self.live.lock();
            let Some(live) = guard.as_mut() else { return };
            let Some(errors) = setup::disarm(&self.plan, &mut live.res, &mut live.journal, i)
            else {
                return;
            };
            drop(guard);
            if errors.is_empty() {
                tracing::info!(
                    interface = %self.plan.interface,
                    endpoint = %endpoint,
                    state = "closed",
                    reason = "socket dropped",
                    "XDP context endpoint released"
                );
            }
            for p in errors {
                tracing::warn!(
                    interface = %self.plan.interface,
                    endpoint = %endpoint,
                    device = p.device.as_ref().map(tracing::field::display),
                    operation = "remove_endpoint",
                    reason = p.reason,
                    error = p.error.as_ref().map(tracing::field::display),
                    state = "degraded",
                    no_socket_check_state = "disabled",
                    action = "restart",
                    "XDP context endpoint release failed"
                );
            }
        }

        fn install_drop_hook(ctx: &Arc<Self>) {
            let weak = Arc::downgrade(ctx);
            ctx.hub.set_drop_hook(Arc::new(move |endpoint| {
                if let Some(ctx) = weak.upgrade() {
                    ctx.endpoint_dropped(endpoint);
                }
            }));
        }

        fn retire_slave(&self, slave: usize) {
            if self.hub.check().is_err() {
                return;
            }
            let bit = if slave < 64 { 1u64 << slave } else { 0 };
            if self.retired.fetch_or(bit, Ordering::SeqCst) & bit != 0 {
                return;
            }
            let interface = self.plan.interface.as_str();
            let name = self
                .plan
                .devices
                .get(slave)
                .map_or("?", |d| d.name.as_str());
            let mut warnings = Vec::new();
            let mut taken = {
                let mut guard = self.live.lock();
                let Some(live) = guard.as_mut() else { return };
                let t = setup::take_device(&mut live.res, &mut live.journal, slave);
                if let Some(t) = t.as_ref() {
                    let cores: Vec<(u32, QueueCore)> = t
                        .unhanded
                        .iter()
                        .map(|b| (b.slot, QueueCore::retired_placeholder(name, b.queue)))
                        .collect();
                    live.res.devices[slave].retired_cores.extend(cores);
                }
                t
            };
            if let Some(t) = taken.as_mut() {
                warnings.extend(setup::disown_retiring(t));
            }
            let pump = self.pump.lock();
            if let Some(p) = pump.as_ref() {
                p.retire_slave(slave);
            }
            drop(pump);
            self.hub.retire_slave(slave);
            if let Some(t) = taken {
                let released = setup::release(&EthtoolNic, t, &mut |f| self.with_try_flock(f));
                let deferring = released.pending.is_some();
                if deferring {
                    let unavailable = released
                        .errors
                        .iter()
                        .any(|p| p.reason == setup::LOCK_UNAVAILABLE);
                    tracing::debug!(
                        bond = %interface,
                        device = %name,
                        operation = "leave_chain",
                        reason = if unavailable { "bpffs lock unavailable" } else { "bpffs lock busy" },
                        path = %monitor::BPFFS_LOCK_PATH,
                        action = "retry",
                        "XDP bond slave chain leave deferred"
                    );
                }
                let mut guard = self.live.lock();
                match guard.as_mut() {
                    Some(live) => {
                        warnings.extend(setup::settle(&mut live.res, &mut live.journal, released));
                        if deferring {
                            self.deferred.store(true, Ordering::SeqCst);
                        }
                    }
                    None => {
                        warnings.extend(released.errors);
                        if !released.forget.is_empty()
                            || !released.kept.is_empty()
                            || released.pending.is_some()
                        {
                            warnings.push(
                                setup::Problem::bare(name, "context torn down meanwhile")
                                    .leaving("record, chain member"),
                            );
                        }
                    }
                }
            }
            for w in &warnings {
                tracing::warn!(
                    bond = %interface,
                    device = w.device.as_ref().map(tracing::field::display),
                    reason = w.reason,
                    error = w.error.as_ref().map(tracing::field::display),
                    location = w.location,
                    leftover = w.leftover,
                    "XDP bond slave retirement incomplete"
                );
            }
            tracing::info!(
                bond = %interface,
                device = %name,
                state = "stopped",
                warning_count = warnings.len(),
                "XDP bond slave retired"
            );
        }

        fn with_try_flock(&self, f: &mut dyn FnMut(setup::TryLock<'_>)) {
            match self.try_flock() {
                Ok(Some(l)) => f(setup::TryLock::Held(l.held())),
                Ok(None) => f(setup::TryLock::Busy),
                Err(e) => f(setup::TryLock::Failed(e)),
            }
        }

        fn try_flock(&self) -> Result<Option<Flock>, String> {
            BpffsLock::try_acquire()
                .map(|l| l.map(Flock::Real))
                .map_err(|e| e.to_string())
        }

        fn wait_flock(&self, bound: Duration) -> Result<Option<Flock>, String> {
            wait_for_lock(bound, || {
                BpffsLock::try_acquire()
                    .map(|l| l.map(Flock::Real))
                    .map_err(|e| e.to_string())
            })
        }

        fn leave_deferred(&self) {
            if !self.deferred.swap(false, Ordering::SeqCst) {
                return;
            }
            let pending = {
                let mut guard = self.live.lock();
                match guard.as_mut() {
                    Some(live) => std::mem::take(&mut live.res.deferred),
                    None => return,
                }
            };
            if pending.is_empty() {
                return;
            }
            let interface = self.plan.interface.as_str();
            let lock = match self.try_flock() {
                Ok(lock) => {
                    self.lock_recovered();
                    lock
                }
                Err(e) => {
                    self.lock_failed(&e);
                    None
                }
            };
            let back = match lock {
                Some(l) => {
                    self.log_leaves(setup::leave_pending(pending, l.held()));
                    return;
                }
                None => {
                    let mut guard = self.live.lock();
                    match guard.as_mut() {
                        Some(live) => {
                            live.res.deferred.extend(pending);
                            self.deferred.store(true, Ordering::SeqCst);
                            return;
                        }
                        None => pending,
                    }
                }
            };
            match self.wait_flock(TEARDOWN_LOCK_WAIT) {
                Ok(Some(l)) => self.log_leaves(setup::leave_pending(back, l.held())),
                Ok(None) => {
                    for p in back {
                        let device = p.name();
                        p.abandon();
                        tracing::warn!(
                            bond = %interface,
                            device = %device,
                            reason = "bpffs lock held by another process",
                            path = %monitor::BPFFS_LOCK_PATH,
                            wait_ms = TEARDOWN_LOCK_WAIT.as_millis(),
                            leftover = "chain member",
                            action = "remove at the next start",
                            "XDP bond slave chain leave failed after teardown"
                        );
                    }
                }
                Err(e) => {
                    for p in back {
                        let device = p.name();
                        p.abandon();
                        tracing::warn!(
                            bond = %interface,
                            device = %device,
                            reason = "bpffs lock unavailable",
                            error = %e,
                            path = %monitor::BPFFS_LOCK_PATH,
                            leftover = "chain member",
                            action = "remove at the next start",
                            "XDP bond slave chain leave failed after teardown"
                        );
                    }
                }
            }
        }

        fn lock_failed(&self, e: &str) {
            let mut st = self.lock_warned.lock();
            let now = Instant::now();
            let (first, note) = match *st {
                None => (true, true),
                Some((_, noted)) => (
                    false,
                    now.saturating_duration_since(noted) >= LOCK_WARN_EVERY,
                ),
            };
            if !note {
                return;
            }
            *st = Some((st.map_or(now, |(since, _)| since), now));
            let retry_delay_ms = monitor::BOND_PERIOD.as_millis();
            if first {
                tracing::warn!(
                    bond = %self.plan.interface,
                    operation = "take_bpffs_lock",
                    path = %monitor::BPFFS_LOCK_PATH,
                    error = %e,
                    action = "retry",
                    retry_delay_ms,
                    "XDP bond bpffs lock failed"
                );
            } else {
                tracing::debug!(
                    bond = %self.plan.interface,
                    operation = "take_bpffs_lock",
                    path = %monitor::BPFFS_LOCK_PATH,
                    error = %e,
                    action = "retry",
                    retry_delay_ms,
                    "XDP bond bpffs lock still failing"
                );
            }
        }

        fn lock_recovered(&self) {
            let Some((since, _)) = self.lock_warned.lock().take() else {
                return;
            };
            tracing::info!(
                bond = %self.plan.interface,
                path = %monitor::BPFFS_LOCK_PATH,
                downtime_ms = since.elapsed().as_millis(),
                state = "recovered",
                "XDP bond bpffs lock recovered"
            );
        }

        fn log_leaves(&self, (left, errors): (Vec<String>, Vec<setup::Problem>)) {
            let interface = self.plan.interface.as_str();
            for p in &errors {
                tracing::warn!(
                    bond = %interface,
                    device = p.device.as_ref().map(tracing::field::display),
                    reason = p.reason,
                    error = p.error.as_ref().map(tracing::field::display),
                    action = "remove at the next start",
                    "XDP bond slave chain leave failed"
                );
            }
            if !left.is_empty() {
                tracing::info!(
                    bond = %interface,
                    devices = %left.join(","),
                    device_count = left.len(),
                    outcome = "completed",
                    "XDP bond slave chain leave completed"
                );
            }
        }

        /// Hands out the socket once, then adds the endpoint to the classifier.
        /// Dropping the last handle removes it from the classifier; a second call is an error.
        pub fn socket(&self, endpoint: &str) -> Result<Arc<XdpQuicSocket>, XdpError> {
            let i = self.endpoint_index(endpoint)?;
            if let Some(f) = self.hub.failed() {
                return Err(XdpError::Failed(f));
            }
            let interface = self.plan.interface.as_str();
            let ep = &self.plan.endpoints[i];
            let facts = iface_facts(interface, Some(endpoint))?;
            let mut guard = self.live.lock();
            let live = guard
                .as_mut()
                .ok_or_else(|| self.shut_down_error(Some(endpoint)))?;
            let taken = || {
                setup_err(
                    interface,
                    None,
                    Some(endpoint),
                    "the endpoint's socket was already handed out",
                    "take each endpoint's socket once",
                )
            };
            if live.res.armed.get(i).copied().unwrap_or(true)
                || live.res.reserved.get(i).is_none_or(Option::is_none)
            {
                return Err(taken());
            }
            let shared = match self.plan.kind {
                setup::LayoutKind::Shared => {
                    let pump = self.pump.lock();
                    let p = pump
                        .as_ref()
                        .ok_or_else(|| self.shut_down_error(Some(endpoint)))?;
                    let inbox = p
                        .inbox(i)
                        .ok_or_else(|| setup::internal(interface, "no inbox for the endpoint"))?;
                    Some((p.tx_queues(), inbox))
                }
                setup::LayoutKind::Dedicated => None,
            };
            let mut picks = Vec::with_capacity(live.res.devices.len());
            if shared.is_none() {
                for (d, dr) in live.res.devices.iter().enumerate() {
                    if dr.retired {
                        if !dr.retired_cores.iter().any(|(slot, _)| *slot == ep.slot) {
                            return Err(setup_err(
                                interface,
                                Some(dr.dev.name()),
                                Some(endpoint),
                                format!(
                                    "bond slave {} was retired and its queue for this endpoint could not be kept",
                                    dr.dev.name()
                                ),
                                "restart the service",
                            ));
                        }
                        picks.push((d, None));
                        continue;
                    }
                    let k = dr
                        .queues
                        .iter()
                        .position(|q| q.as_ref().is_some_and(|q| q.slot == ep.slot))
                        .ok_or_else(taken)?;
                    picks.push((d, Some(k)));
                }
            }
            let kernel = live.res.reserved[i].take().ok_or_else(taken)?;
            let kernel = KernelSock::new(kernel).map_err(|e| {
                setup_err(
                    interface,
                    None,
                    Some(endpoint),
                    format!("cannot set up the endpoint's kernel UDP socket: {e}"),
                    "report this",
                )
            })?;
            let (queues, rx) = match shared {
                Some((queues, inbox)) => (queues, RxSource::Inbox(inbox)),
                None => {
                    let mut queues = Vec::with_capacity(picks.len());
                    let mut halves = Vec::with_capacity(picks.len());
                    let mut opened = Vec::with_capacity(picks.len());
                    for (d, k) in picks {
                        let dr = &mut live.res.devices[d];
                        let Some(k) = k else {
                            let at = dr
                                .retired_cores
                                .iter()
                                .position(|(slot, _)| *slot == ep.slot)
                                .ok_or_else(taken)?;
                            queues.push(dr.retired_cores.swap_remove(at).1);
                            continue;
                        };
                        let bound = dr.queues[k].take().ok_or_else(taken)?;
                        opened.push(d);
                        match take_over(interface, dr.dev.name(), Some(endpoint), bound, &facts) {
                            Ok((rx, core)) => {
                                halves.push((d, rx));
                                queues.push(core);
                            }
                            Err(e) => {
                                for w in setup::forget_sockets(
                                    &mut live.res,
                                    &mut live.journal,
                                    &opened,
                                    ep.slot,
                                ) {
                                    tracing::warn!(
                                        interface = %interface,
                                        endpoint = %endpoint,
                                        operation = "remove_socket",
                                        error = %w,
                                        "XDP context socket cleanup failed"
                                    );
                                }
                                return Err(e);
                            }
                        }
                    }
                    (queues.into(), RxSource::Own(halves))
                }
            };
            let mut xdp_ifindexes = vec![facts.ifindex];
            xdp_ifindexes.extend(self.plan.devices.iter().map(|d| d.ifindex));
            let s = XdpQuicSocket::new(
                Arc::clone(&self.hub),
                SocketParts {
                    endpoint: ep.name,
                    local: SocketAddrV4::new(*ep.listen.ip(), live.res.ports[i]),
                    xdp_ifindexes,
                    queues,
                    rx,
                    kernel,
                    routes: Arc::clone(&self.routes),
                    peers: PeerTable::new(socket::PEER_SLOTS),
                    elig: Arc::clone(&self.elig),
                },
            );
            let armed = setup::arm(&self.plan, &mut live.res, &mut live.journal, i);
            drop(guard);
            armed?;
            Ok(s)
        }

        /// Undoes setup in reverse order; idempotent, also run on drop. Blocks for seconds:
        /// never call it on a latency runtime thread; async callers use `spawn_blocking`.
        pub fn shutdown(&self) {
            self.hub.shut_down();
            let m = self.monitor.lock().take();
            if let Some(m) = m {
                m.stop();
            }
            self.teardown();
            let pump = self.pump.lock().take();
            if let Some(mut p) = pump {
                p.stop();
            }
            self.hub.retire_sockets();
            self.hub.stop_service();
        }

        fn teardown(&self) {
            let mut guard = self.live.lock();
            let Some(mut live) = guard.take() else { return };
            if live.journal.len() == 0 && live.res.deferred.is_empty() {
                return;
            }
            let lock = match self.wait_flock(TEARDOWN_LOCK_WAIT) {
                Ok(Some(lock)) => Some(lock),
                Ok(None) => {
                    tracing::warn!(
                        interface = %self.plan.interface,
                        path = %monitor::BPFFS_LOCK_PATH,
                        wait_ms = TEARDOWN_LOCK_WAIT.as_millis(),
                        reason = "bpffs lock held by another process",
                        released = "sockets, keys, rules, record",
                        leftover = "chain member",
                        action = "remove at the next start",
                        "XDP context teardown without the bpffs lock"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        interface = %self.plan.interface,
                        path = %monitor::BPFFS_LOCK_PATH,
                        reason = "bpffs lock unavailable",
                        error = %e,
                        released = "sockets, keys, rules, record",
                        leftover = "chain member",
                        action = "remove at the next start",
                        "XDP context teardown without the bpffs lock"
                    );
                    None
                }
            };
            let pending = std::mem::take(&mut live.res.deferred);
            self.deferred.store(false, Ordering::SeqCst);
            let mut errors = setup::teardown(
                &EthtoolNic,
                lock.as_ref().and_then(Flock::real),
                &self.plan,
                &mut live.res,
                &mut live.journal,
            );
            errors.extend(setup::finish_pending(
                pending,
                lock.as_ref().map(Flock::held),
            ));
            drop(lock);
            for p in &errors {
                log_teardown_problem(&self.plan.interface, p);
            }
            let reason = if self.hub.failed().is_some() {
                "context failed"
            } else {
                "shutdown"
            };
            tracing::info!(
                interface = %self.plan.interface,
                state = "stopped",
                reason,
                error_count = errors.len(),
                "XDP context stopped"
            );
        }

        fn endpoint_index(&self, endpoint: &str) -> Result<usize, XdpError> {
            self.plan
                .endpoints
                .iter()
                .position(|e| e.name == endpoint)
                .ok_or_else(|| {
                    setup_err(
                        &self.plan.interface,
                        None,
                        Some(endpoint),
                        "no such endpoint in this context",
                        "list every endpoint when building the context",
                    )
                })
        }

        fn shut_down_error(&self, endpoint: Option<&str>) -> XdpError {
            XdpError::ShutDown {
                interface: self.plan.interface.clone(),
                endpoint: endpoint.map(str::to_string),
            }
        }
    }

    impl Drop for XdpContext {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    impl fmt::Debug for XdpContext {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("XdpContext")
                .field("summary", &self.summary)
                .finish_non_exhaustive()
        }
    }

    struct Watched {
        routes: Arc<Routes>,
        events: NetlinkSocket,
        xdp: Vec<u32>,
        health: Vec<HealthDev>,
    }

    fn watch_routes(plan: &Plan, res: &Resources) -> Result<Watched, XdpError> {
        let interface = plan.interface.as_str();
        let err = |what: String| {
            setup_err(
                interface,
                None,
                None,
                what,
                "check the network namespace (`ip route`, `ip neigh`)",
            )
        };
        let events = NetlinkSocket::bind(monitor::EVENT_GROUPS)
            .map_err(|e| err(format!("cannot subscribe to routing events: {e}")))?;
        let master = NetworkDevice::new(interface)
            .map_err(|e| err(format!("{interface} cannot be found: {e}")))?
            .if_index();
        let mut xdp = vec![master];
        xdp.extend(
            plan.devices
                .iter()
                .map(|d| d.ifindex)
                .filter(|i| *i != master),
        );
        let snap = monitor::build_snapshot(&xdp).map_err(|e| {
            err(format!(
                "cannot read the routing, neighbor, link and address tables: {e}"
            ))
        })?;
        let endpoint_addrs: Vec<Ipv4Addr> = plan
            .endpoints
            .iter()
            .flat_map(|e| e.addrs.iter().copied())
            .collect();
        if let Some((reason, remedy)) = snap.setup_blocker(interface, &endpoint_addrs) {
            return Err(setup_err(interface, None, None, reason, &remedy));
        }
        let mut health = Vec::with_capacity(res.devices.len());
        for dr in &res.devices {
            let member = dr
                .dispatcher
                .as_ref()
                .ok_or_else(|| setup::internal(interface, "no chain member after setup"))?
                .member_id()
                .map_err(|e| {
                    setup::internal(
                        interface,
                        &format!("cannot read our member's program id: {e}"),
                    )
                })?;
            health.push(HealthDev {
                name: dr.dev.name().to_string(),
                ifindex: dr.dev.if_index(),
                member,
            });
        }
        Ok(Watched {
            routes: Routes::new(interface, snap),
            events,
            xdp,
            health,
        })
    }

    fn socket_label(plan: &Plan, device: &str, slot: u32, queue: u32) -> String {
        let mut eps = plan
            .endpoints
            .iter()
            .filter(|e| e.slot == slot)
            .map(|e| e.name);
        match (eps.next(), eps.next()) {
            (Some(name), None) => {
                format!("the AF_XDP socket of {device} queue {queue} (endpoint {name})")
            }
            _ => format!("the AF_XDP socket of {device} queue {queue} (slot {slot})"),
        }
    }

    fn take_over(
        interface: &str,
        device: &str,
        endpoint: Option<&str>,
        bound: setup::BoundQueue,
        facts: &IfaceFacts,
    ) -> Result<(socket::RxImpl, QueueCore), XdpError> {
        let queue = bound.queue;
        let (rx, tx, probe) = rings::split(bound).map_err(|e| {
            setup_err(
                interface,
                (device != interface).then_some(device),
                endpoint,
                format!("cannot take over the AF_XDP socket of queue {queue}: {e}"),
                "report this",
            )
        })?;
        let (rx, tx, probe) = socket::own_queue(rx, tx, probe);
        Ok(QueueParts {
            rx,
            tx,
            probe,
            device: device.to_string(),
            queue,
            mac: facts.mac,
            mtu: facts.mtu,
            primary_ip: facts.primary_ip,
        }
        .into_core())
    }

    fn start_pump(plan: &Plan, res: &mut Resources, hub: &Arc<Hub>) -> Result<Pump, XdpError> {
        let interface = plan.interface.as_str();
        let facts = iface_facts(interface, None)?;
        let mut rxs = Vec::new();
        let mut tx = Vec::with_capacity(res.devices.len());
        for (d, dr) in res.devices.iter_mut().enumerate() {
            let slave =
                u8::try_from(d).map_err(|_| setup::internal(interface, "more than 255 devices"))?;
            let mut first = true;
            for slot in dr.queues.iter_mut() {
                let Some(bound) = slot.take() else { continue };
                let (rx, core) = take_over(interface, dr.dev.name(), None, bound, &facts)?;
                if std::mem::take(&mut first) {
                    tx.push(core);
                    rxs.push((rx, None, slave));
                } else {
                    rxs.push((rx, Some(core), slave));
                }
            }
            if first {
                return Err(setup::internal(
                    interface,
                    &format!("{} has no AF_XDP socket", dr.dev.name()),
                ));
            }
        }
        let tx: Arc<[QueueCore]> = tx.into();
        let mut queues = Vec::with_capacity(rxs.len());
        for (rx, core, slave) in rxs {
            queues.push(match core {
                Some(core) => PumpQueue::own(rx, core, slave),
                None => PumpQueue::tx(rx, &tx, usize::from(slave), slave).ok_or_else(|| {
                    setup::internal(interface, "transmit queue index out of range")
                })?,
            });
        }
        let routes: Vec<(Ipv4Addr, u16, usize)> = plan
            .endpoints
            .iter()
            .enumerate()
            .flat_map(|(i, e)| {
                let port = res.ports[i];
                e.addrs.iter().map(move |a| (*a, port, i))
            })
            .collect();
        let (mut pump, reader) =
            Pump::new(Arc::clone(hub), queues, &routes, plan.endpoints.len(), tx);
        pump.spawn(reader).map_err(|e| {
            setup_err(
                interface,
                None,
                None,
                format!("cannot start the XDP pump thread: {e}"),
                "check the process thread limit",
            )
        })?;
        Ok(pump)
    }

    const fn is_bit(mask: u64, i: usize) -> bool {
        i < 64 && mask & (1u64 << i) != 0
    }

    fn first_eligibility(plan: &Plan, elig: &Eligibility) -> BondState {
        let interface = plan.interface.as_str();
        let names: Vec<&str> = plan.devices.iter().map(|d| d.name.as_str()).collect();
        let (mask, verdicts) = slaves::eligibility(&SysfsRoot::system(), interface, &names);
        let now = Instant::now();
        let mut failing = Vec::new();
        for (name, v) in names.iter().zip(&verdicts) {
            let device = (*name).to_string();
            let ev = match v {
                Ok(()) => BondEvent::Eligible { device },
                Err(Ineligible::Unreadable(e)) => {
                    if failing.contains(&e.path) {
                        continue;
                    }
                    failing.push(e.path.clone());
                    BondEvent::ReadFailed {
                        path: e.path.clone(),
                        error: e.error.clone(),
                    }
                }
                Err(reason) => BondEvent::NotEligible {
                    device,
                    reason: reason.clone(),
                },
            };
            monitor::log_bond(interface, &ev);
        }
        elig.publish(mask);
        let managed = plan
            .devices
            .iter()
            .enumerate()
            .map(|(slave, d)| Managed {
                name: d.name.clone(),
                ifindex: d.ifindex,
                slave,
            })
            .collect();
        let mut st = BondState::new(managed, mask);
        for path in &failing {
            st.note_failing(path, now);
        }
        st
    }

    const fn device_mask(devices: usize) -> u64 {
        if devices >= 64 {
            u64::MAX
        } else {
            (1u64 << devices) - 1
        }
    }

    fn log_teardown_problem(interface: &str, p: &setup::Problem) {
        let device = p.device.as_ref().map(tracing::field::display);
        let error = p.error.as_ref().map(tracing::field::display);
        let path = p.path.as_ref().map(tracing::field::display);
        if p.attention {
            tracing::error!(
                interface = %interface,
                device,
                reason = p.reason,
                error,
                path,
                rule_count = p.rule_count,
                action = "check and remove by hand",
                "XDP context teardown failed"
            );
        } else {
            tracing::warn!(
                interface = %interface,
                device,
                reason = p.reason,
                error,
                path,
                rule_count = p.rule_count,
                leftover = p.leftover,
                action = if p.leftover.is_some() { "remove at the next start" } else { "none" },
                "XDP context teardown incomplete"
            );
        }
    }

    fn summarize(plan: &Plan, ports: &[u16]) -> XdpSummary {
        let mut drivers: Vec<&str> = Vec::new();
        for d in &plan.devices {
            if !drivers.contains(&d.driver.as_str()) {
                drivers.push(&d.driver);
            }
        }
        XdpSummary {
            interface: plan.interface.clone(),
            devices: plan.devices.iter().map(|d| d.name.clone()).collect(),
            driver: drivers.join(","),
            mode: plan.mode,
            zero_copy: plan.zero_copy,
            bond: plan.bond,
            layout: plan.kind.name(),
            queues: plan
                .devices
                .iter()
                .map(|d| (d.name.clone(), d.queues()))
                .collect(),
            endpoints: plan
                .endpoints
                .iter()
                .zip(ports)
                .map(|(e, port)| (e.name, SocketAddrV4::new(*e.listen.ip(), *port)))
                .collect(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use other::XdpContext;

#[cfg(not(target_os = "linux"))]
mod other {
    use super::*;

    #[derive(Debug)]
    pub struct XdpContext {
        never: std::convert::Infallible,
    }

    impl XdpContext {
        pub fn new(
            _settings: &XdpSettings,
            _endpoints: &[EndpointSpec],
        ) -> Result<Arc<Self>, XdpError> {
            Err(XdpError::Unsupported)
        }

        pub fn local_addr(&self, _endpoint: &str) -> Option<SocketAddrV4> {
            match self.never {}
        }

        pub fn summary(&self) -> XdpSummary {
            match self.never {}
        }

        pub fn failed(&self) -> Option<XdpFailure> {
            match self.never {}
        }

        pub async fn wait_failed(&self) -> XdpFailure {
            match self.never {}
        }

        pub fn pump_metrics(&self) -> Option<PumpMetrics> {
            match self.never {}
        }

        pub fn eligible_slaves(&self) -> u64 {
            match self.never {}
        }

        pub fn no_socket_drops(&self) -> Result<u64, XdpError> {
            match self.never {}
        }

        pub fn shutdown(&self) {
            match self.never {}
        }

        pub fn socket(&self, _endpoint: &str) -> Result<Arc<crate::XdpQuicSocket>, XdpError> {
            match self.never {}
        }

        pub async fn prepare(&self, _dest: SocketAddr) -> Result<(), XdpError> {
            match self.never {}
        }
    }
}
