
use {
    crate::{
        error::{DropReason, XdpError, XdpFailure},
        slaves::{
            Eligibility, Ineligible, MembershipEvent, ReadError, SlaveState, SysfsRoot, judge,
            membership_diff,
        },
        dispatcher::ChainState,
        netlink::netlink_get_routes,
        netlink::{
            LinkInfo, NetlinkSocket, netlink_get_ipv4_addrs, netlink_get_links,
            netlink_use_neighbor,
        },
        quic::socket::Hub,
        route::{
            Interfaces, Neighbors, Route, RouteTable, Router, Routes as RouteList, RoutingTables,
        },
    },
    arc_swap::ArcSwap,
    parking_lot::Mutex,
    std::{
        collections::{HashMap, HashSet},
        error::Error,
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread::JoinHandle,
        time::{Duration, Instant},
    },
};

pub(crate) const HEALTH_PERIOD: Duration = Duration::from_secs(1);
pub(crate) const TX_STALL: Duration = Duration::from_secs(5);
pub(crate) const PREPARE_TIMEOUT: Duration = Duration::from_secs(2);
const USED_WINDOW: Duration = Duration::from_secs(30);
const USE_RESOLVED: Duration = Duration::from_secs(10);
const USE_UNRESOLVED: Duration = Duration::from_secs(1);
pub(crate) const UNREADABLE_PERIODS: u32 = 3;
const REBUILD_GAP: Duration = Duration::from_millis(10);
const POLL_STEP: Duration = Duration::from_millis(100);
const READ_RETRY_STEP: Duration = Duration::from_millis(10);
const MONITOR_JOIN: Duration = Duration::from_secs(1);
const MARK_SLOTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NextHop {
    Xdp {
        mac: [u8; 6],
    },
    Kernel,
    OtherInterface {
        name: String,
    },
    Unresolved,
    Multipath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolved {
    Xdp {
        mac: [u8; 6],
        hop: Ipv4Addr,
        ifindex: u32,
        refresh: bool,
    },
    Kernel,
    Other {
        ifindex: u32,
    },
    Unresolved {
        hop: Option<(Ipv4Addr, u32)>,
    },
    Multipath {
        prefix: (Ipv4Addr, u8),
    },
}

pub(crate) struct Snapshot {
    router: Router,
    links: Vec<LinkInfo>,
    same_host: Vec<u32>,
    local: Vec<Ipv4Addr>,
    addrs: Vec<(u32, Ipv4Addr)>,
    xdp: Vec<u32>,
    multipath: Vec<(Ipv4Addr, u8)>,
    multipath_priority: Vec<u32>,
    nexthop_objects: Vec<(Ipv4Addr, u8)>,
}

const fn covers(prefix: (Ipv4Addr, u8), dest: Ipv4Addr) -> bool {
    let (net, len) = prefix;
    if len == 0 {
        return true;
    }
    let shift = if len >= 32 { 0 } else { 32 - len as u32 };
    let (a, b) = (
        u32::from_be_bytes(net.octets()),
        u32::from_be_bytes(dest.octets()),
    );
    a >> shift == b >> shift
}

impl Snapshot {
    pub(crate) fn from_tables(
        tables: RoutingTables,
        mut links: Vec<LinkInfo>,
        addrs: Vec<(u32, Ipv4Addr)>,
        xdp: &[u32],
        multipath: Vec<(Ipv4Addr, u8, u32)>,
    ) -> io::Result<Self> {
        let router = Router::from_tables(tables)?;
        links.sort_by_key(|l| l.if_index);
        let mut same_host: Vec<u32> = links
            .iter()
            .filter(|l| !xdp.contains(&l.if_index))
            .filter(|l| l.is_loopback() || matches!(l.kind.as_deref(), Some("bridge" | "veth")))
            .map(|l| l.if_index)
            .collect();
        same_host.sort_unstable();
        let mut local: Vec<Ipv4Addr> = addrs.iter().map(|(_, ip)| *ip).collect();
        local.sort_unstable();
        local.dedup();
        let multipath_priority = multipath.iter().map(|m| m.2).collect();
        let multipath = multipath.into_iter().map(|(d, l, _)| (d, l)).collect();
        Ok(Self {
            router,
            links,
            same_host,
            local,
            addrs,
            xdp: xdp.to_vec(),
            multipath,
            multipath_priority,
            nexthop_objects: Vec::new(),
        })
    }

    pub(crate) fn with_nexthop_objects(mut self, prefixes: Vec<(Ipv4Addr, u8)>) -> Self {
        self.nexthop_objects = prefixes;
        self
    }

    pub(crate) fn is_nexthop_object(&self, prefix: (Ipv4Addr, u8)) -> bool {
        self.nexthop_objects.contains(&prefix)
    }

    pub(crate) fn nexthop_object_blocker(&self, endpoint_addrs: &[Ipv4Addr]) -> Option<String> {
        if self.nexthop_objects.is_empty() {
            return None;
        }
        if self.is_nexthop_object((Ipv4Addr::UNSPECIFIED, 0)) {
            return Some("the default route (0.0.0.0/0)".into());
        }
        let gateway = match self.router.default().ok().map(|h| h.ip_addr) {
            Some(IpAddr::V4(gw)) => Some(gw),
            _ => None,
        };
        let covering = |ip: Ipv4Addr| {
            self.multipath_for(ip)
                .filter(|p| self.is_nexthop_object(*p))
        };
        for ip in endpoint_addrs {
            if let Some((net, len)) = covering(*ip) {
                return Some(format!(
                    "the route to {net}/{len}, which covers the endpoint address {ip}"
                ));
            }
        }
        let (net, len) = gateway.and_then(covering)?;
        Some(format!(
            "the route to {net}/{len}, which covers the default gateway {}",
            gateway?
        ))
    }

    pub(crate) fn setup_blocker(
        &self,
        interface: &str,
        endpoint_addrs: &[Ipv4Addr],
    ) -> Option<(String, String)> {
        if let Some(what) = self.nexthop_object_blocker(endpoint_addrs) {
            return Some((
                format!(
                    "{what} uses a kernel nexthop object (nhid) and carries no output interface or gateway \
                     (net.ipv4.nexthop_compat_mode=0), so the XDP path cannot resolve its next hop"
                ),
                format!(
                    "set `sysctl -w net.ipv4.nexthop_compat_mode=1`, or replace it with a classic route \
                     (`ip route replace <prefix> via <gateway> dev {interface}`)"
                ),
            ));
        }
        if self.multipath.iter().any(|(_, len)| *len == 0) {
            return Some((
                format!(
                    "the route to 0.0.0.0/0 (default) is multipath (ECMP); the XDP path needs a single next hop on {interface}"
                ),
                format!(
                    "make the default route a single next hop on {interface} (`ip route replace default via <gateway> dev {interface}`)"
                ),
            ));
        }
        None
    }

    fn multipath_for(&self, dest: Ipv4Addr) -> Option<(Ipv4Addr, u8)> {
        let (m, prio) = self
            .multipath
            .iter()
            .copied()
            .zip(self.multipath_priority.iter().copied())
            .filter(|(m, _)| covers(*m, dest))
            .max_by_key(|((_, len), prio)| (*len, std::cmp::Reverse(*prio)))?;
        match self.router.lookup_route_v4(dest) {
            Some(r) if r.dst_len > m.1 => None,
            Some(r) if r.dst_len == m.1 && r.priority.unwrap_or(0) < prio => None,
            _ => Some(m),
        }
    }

    #[inline]
    fn resolve(&self, dest: Ipv4Addr) -> Resolved {
        if dest.is_loopback() || self.local.binary_search(&dest).is_ok() {
            return Resolved::Kernel;
        }
        if !self.multipath.is_empty()
            && let Some(prefix) = self.multipath_for(dest)
        {
            return Resolved::Multipath { prefix };
        }
        let Ok(h) = self.router.route_v4(dest) else {
            return Resolved::Unresolved { hop: None };
        };
        let IpAddr::V4(hop) = h.ip_addr else {
            return Resolved::Unresolved { hop: None };
        };
        if self.xdp.contains(&h.if_index) {
            return match h.mac_addr {
                Some(m) => Resolved::Xdp {
                    mac: m.0,
                    hop,
                    ifindex: h.if_index,
                    refresh: h.neigh_requires_refresh,
                },
                None => Resolved::Unresolved {
                    hop: Some((hop, h.if_index)),
                },
            };
        }
        if self.same_host.binary_search(&h.if_index).is_ok() {
            return Resolved::Kernel;
        }
        Resolved::Other {
            ifindex: h.if_index,
        }
    }

    fn link(&self, ifindex: u32) -> Option<&LinkInfo> {
        self.links
            .binary_search_by_key(&ifindex, |l| l.if_index)
            .ok()
            .and_then(|i| self.links.get(i))
    }

    fn name(&self, ifindex: u32) -> String {
        self.link(ifindex)
            .map_or_else(|| format!("ifindex {ifindex}"), |l| l.name.clone())
    }

    fn carrier(&self, ifindex: u32) -> Option<bool> {
        self.link(ifindex).map(LinkInfo::carrier)
    }

    fn default_hop(&self) -> Option<(Ipv4Addr, u32)> {
        let h = self.router.default().ok()?;
        match h.ip_addr {
            IpAddr::V4(ip) if self.xdp.contains(&h.if_index) && h.neigh_requires_refresh => {
                Some((ip, h.if_index))
            }
            _ => None,
        }
    }
}

pub(crate) fn build_snapshot(xdp: &[u32]) -> io::Result<Snapshot> {
    let mut tries = 0;
    loop {
        match read_tables(xdp) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted && tries < 10 => {
                tries += 1;
                std::thread::sleep(READ_RETRY_STEP);
            }
            r => return r,
        }
    }
}

fn read_tables(xdp: &[u32]) -> io::Result<Snapshot> {
    let entries = netlink_get_routes(libc::AF_INET as u8, u32::from(RouteTable::Main))?;
    let mut multipath = Vec::new();
    let mut nexthop_objects = Vec::new();
    let mut single = Vec::with_capacity(entries.len());
    for e in entries {
        let nh_only = e.nh_id && !e.multipath && e.out_if_index.is_none();
        if e.multipath || nh_only {
            if let Some(IpAddr::V4(d)) = e.destination.or(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))) {
                let prefix = (d, e.dst_len.min(32));
                multipath.push((prefix.0, prefix.1, e.priority.unwrap_or(0)));
                if nh_only {
                    nexthop_objects.push(prefix);
                }
            }
        } else if let Ok(r) = Route::try_from(e) {
            single.push(r);
        }
    }
    let tables = RoutingTables::new(
        RouteList::new(RouteTable::Main, single),
        Neighbors::from_netlink()?,
        Interfaces::from_netlink()?,
    );
    Ok(Snapshot::from_tables(
        tables,
        netlink_get_links()?,
        netlink_get_ipv4_addrs()?,
        xdp,
        multipath,
    )?
    .with_nexthop_objects(nexthop_objects))
}

pub(crate) struct Routes {
    snap: ArcSwap<Snapshot>,
    marks: Box<[AtomicU64]>,
    generation: tokio::sync::watch::Sender<u64>,
    refresh_errors: AtomicU64,
    interface: String,
}

#[inline]
const fn mark_slot(ip: Ipv4Addr) -> usize {
    (u32::from_be_bytes(ip.octets()).wrapping_mul(0x9E37_79B1) >> 24) as usize % MARK_SLOTS
}

impl Routes {
    pub(crate) fn new(interface: &str, s: Snapshot) -> Arc<Self> {
        Arc::new(Self {
            snap: ArcSwap::from_pointee(s),
            marks: (0..MARK_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            generation: tokio::sync::watch::Sender::new(0),
            refresh_errors: AtomicU64::new(0),
            interface: interface.to_string(),
        })
    }

    #[inline]
    pub(crate) fn resolve(&self, dest: Ipv4Addr) -> Resolved {
        self.snap.load().resolve(dest)
    }

    pub(crate) fn next_hop(&self, dest: Ipv4Addr) -> NextHop {
        let s = self.snap.load();
        match s.resolve(dest) {
            Resolved::Xdp { mac, .. } => NextHop::Xdp { mac },
            Resolved::Kernel => NextHop::Kernel,
            Resolved::Other { ifindex } => NextHop::OtherInterface {
                name: s.name(ifindex),
            },
            Resolved::Unresolved { .. } => NextHop::Unresolved,
            Resolved::Multipath { .. } => NextHop::Multipath,
        }
    }

    #[inline]
    pub(crate) fn is_same_host_rx(&self, ifindex: u32, src: Ipv4Addr) -> bool {
        let snap = self.snap.load();
        snap.same_host.binary_search(&ifindex).is_ok() || snap.local.binary_search(&src).is_ok()
    }

    #[inline]
    pub(crate) fn mark_used(&self, ifindex: u32, hop: Ipv4Addr) {
        if let Some(m) = self.marks.get(mark_slot(hop)) {
            m.store(
                (u64::from(ifindex) << 32) | u64::from(u32::from_be_bytes(hop.octets())),
                Ordering::Relaxed,
            );
        }
    }

    fn take_marks(&self) -> Vec<(u32, Ipv4Addr)> {
        let mut out = Vec::new();
        for m in self.marks.iter() {
            if m.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let v = m.swap(0, Ordering::Relaxed);
            if v != 0 {
                out.push(((v >> 32) as u32, Ipv4Addr::from((v as u32).to_be_bytes())));
            }
        }
        out
    }

    pub(crate) fn publish(&self, s: Snapshot) {
        self.snap.store(Arc::new(s));
        self.generation.send_modify(|g| *g = g.wrapping_add(1));
    }

    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.load_full()
    }

    pub(crate) fn refresh_errors(&self) -> u64 {
        self.refresh_errors.load(Ordering::Relaxed)
    }
}

const fn unreachable(dest: SocketAddr, reason: String) -> XdpError {
    XdpError::Unreachable { dest, reason }
}

enum Step {
    Done,
    Wait((Ipv4Addr, u32)),
}

fn decide(routes: &Routes, dest: SocketAddr, ip: Ipv4Addr) -> Result<Step, XdpError> {
    match routes.resolve(ip) {
        Resolved::Xdp {
            hop,
            ifindex,
            refresh,
            ..
        } => {
            if refresh {
                routes.mark_used(ifindex, hop);
            }
            Ok(Step::Done)
        }
        Resolved::Kernel => Ok(Step::Done),
        Resolved::Other { ifindex } => {
            let name = routes.snap.load().name(ifindex);
            Err(unreachable(
                dest,
                format!(
                    "{dest} is routed via {name}, not the XDP interface {}",
                    routes.interface
                ),
            ))
        }
        Resolved::Multipath { prefix } if routes.snap.load().is_nexthop_object(prefix) => {
            Err(unreachable(
                dest,
                format!(
                    "{dest} is routed via a nexthop-object route (nhid, no output interface or gateway), which the XDP path cannot resolve"
                ),
            ))
        }
        Resolved::Multipath { .. } => Err(unreachable(
            dest,
            format!(
                "{dest} is routed via a multipath (ECMP) route, which the XDP path does not support"
            ),
        )),
        Resolved::Unresolved { hop: Some(hop) } => Ok(Step::Wait(hop)),
        Resolved::Unresolved { hop: None } => Err(unreachable(
            dest,
            format!("next hop unreachable: no route to {ip}"),
        )),
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Stopped {
    Failed(XdpFailure),
    ShutDown,
}

pub(crate) async fn prepare(
    routes: &Routes,
    dest: SocketAddr,
    probe: impl FnOnce(Ipv4Addr) -> io::Result<()>,
    timeout: Duration,
    stopped: impl Future<Output = Stopped>,
) -> Result<(), XdpError> {
    let SocketAddr::V4(d) = dest else {
        return Err(unreachable(
            dest,
            "IPv6 destinations are not supported: the XDP path carries IPv4 only".into(),
        ));
    };
    let ip = *d.ip();
    let mut rx = routes.generation.subscribe();
    let (h, ifindex) = match decide(routes, dest, ip)? {
        Step::Done => return Ok(()),
        Step::Wait(hop) => hop,
    };
    routes.mark_used(ifindex, h);
    probe(h).map_err(|e| {
        unreachable(
            dest,
            format!("next hop unreachable: cannot ask the kernel to resolve {h}: {e}"),
        )
    })?;
    let wait = tokio::time::timeout(timeout, async {
        loop {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if let Step::Done = decide(routes, dest, ip)? {
                return Ok(());
            }
        }
    });
    let mut wait = std::pin::pin!(wait);
    let mut stopped = std::pin::pin!(stopped);
    let waited = std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(s) = stopped.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(s));
        }
        wait.as_mut().poll(cx).map(Ok)
    })
    .await;
    match waited {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err(unreachable(
            dest,
            format!("next hop unreachable: {h} did not resolve within {timeout:?}"),
        )),
        Err(Stopped::Failed(f)) => Err(XdpError::Failed(f)),
        Err(Stopped::ShutDown) => Err(unreachable(
            dest,
            "the XDP context was shut down while waiting for the next hop".into(),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unread {
    pub what: String,
    pub error: String,
}

pub(crate) type Read<T> = Result<T, Unread>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockObs {
    Held,
    Busy,
}

pub(crate) const BPFFS_LOCK_PATH: &str = "/sys/fs/bpf/xdp";
pub(crate) const LOCK_BUSY_LIMIT: Duration = Duration::from_secs(30);
const LOCK_BUSY_NOTE_PERIODS: u32 = 3;

#[derive(Clone, Debug)]
pub(crate) struct DeviceObs {
    pub name: String,
    pub chain: Read<ChainState>,
    pub drops: Read<Option<u64>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TxObs {
    pub device: String,
    pub queue: u32,
    pub submitted: u32,
    pub completed: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub now: Instant,
    pub lock: Read<LockObs>,
    pub devices: Vec<DeviceObs>,
    pub sockets: Vec<(String, Read<bool>)>,
    pub rules: Read<Result<(), String>>,
    pub tx: Vec<TxObs>,
    pub carrier: Vec<(String, Option<bool>)>,
    pub routing: Read<()>,
    pub bond: Vec<Unread>,
    pub ineligible: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct TxTrack {
    completed: u32,
    since: Instant,
    up: bool,
    kicked: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HealthState {
    unreadable: HashMap<String, u32>,
    drops: HashMap<String, u64>,
    tx: HashMap<String, TxTrack>,
    busy_since: Option<Instant>,
    busy_periods: u32,
    busy_noted: bool,
    unlocked_missing: HashMap<String, u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub cause: Option<String>,
    pub kick: Vec<Kick>,
    pub events: Vec<HealthEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HealthEvent {
    LockBusy { periods: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Kick {
    pub device: String,
    pub queue: u32,
    pub waited: Duration,
}

fn log_health(interface: &str, ev: &HealthEvent) {
    match ev {
        HealthEvent::LockBusy { periods } => tracing::warn!(
            interface = %interface,
            path = %BPFFS_LOCK_PATH,
            period_count = *periods,
            state = "degraded",
            reason = "held by another process",
            action = "read without lock",
            "XDP monitor bpffs lock busy"
        ),
    }
}

fn log_kick(interface: &str, k: &Kick) {
    tracing::warn!(
        interface = %interface,
        device = %k.device,
        queue = k.queue,
        waited_ms = k.waited.as_millis(),
        state = "degraded",
        reason = "no transmit completion",
        action = "kick",
        "XDP monitor transmit queue kicked"
    );
}

fn chain_breach(name: &str, state: ChainState) -> Option<String> {
    match state {
        ChainState::Present => None,
        ChainState::Detached => Some(format!(
            "{name}: our XDP program was detached (nothing is attached to {name} any more)"
        )),
        ChainState::NotADispatcher(id) => Some(format!(
            "{name}: the XDP program on {name} was replaced by program {id}, which is not a dispatcher; our classifier is gone"
        )),
        ChainState::Missing(id) => Some(format!(
            "{name}: our classifier is no longer in the chain of the XDP dispatcher attached to {name} (program {id})"
        )),
    }
}

pub(crate) fn evaluate(prev: &HealthState, obs: &Observation) -> (HealthState, Outcome) {
    let mut next = HealthState::default();
    let mut out = Outcome::default();
    let mut cause: Option<String> = None;
    let mut breach = |c: String| {
        if cause.is_none() {
            cause = Some(c);
        }
    };
    let mut failed_reads: Vec<&Unread> = Vec::new();

    let locked = matches!(obs.lock, Ok(LockObs::Held));
    match &obs.lock {
        Ok(LockObs::Busy) => {
            let since = prev.busy_since.unwrap_or(obs.now);
            next.busy_since = Some(since);
            next.busy_periods = prev.busy_periods + 1;
            next.busy_noted = prev.busy_noted;
            if next.busy_periods > LOCK_BUSY_NOTE_PERIODS && !prev.busy_noted {
                next.busy_noted = true;
                out.events.push(HealthEvent::LockBusy {
                    periods: next.busy_periods,
                });
            }
            let held = obs.now.saturating_duration_since(since);
            if held >= LOCK_BUSY_LIMIT {
                breach(format!(
                    "XDP health check: the bpffs lock {BPFFS_LOCK_PATH} has been held by another process for {}s, so the XDP \
                     chain cannot be verified; find the holder (`fuser -v {BPFFS_LOCK_PATH}` or `lsof {BPFFS_LOCK_PATH}`)",
                    held.as_secs()
                ));
            }
        }
        Ok(LockObs::Held) => {}
        Err(u) => failed_reads.push(u),
    }

    for d in &obs.devices {
        match &d.chain {
            Ok(ChainState::Present) => {}
            Ok(state @ (ChainState::Missing(_) | ChainState::NotADispatcher(_))) if !locked => {
                let n = prev.unlocked_missing.get(&d.name).copied().unwrap_or(0) + 1;
                if n >= 2
                    && let Some(c) = chain_breach(&d.name, *state)
                {
                    breach(format!(
                        "{c} (seen in 2 consecutive periods while the bpffs lock was held by another process)"
                    ));
                }
                next.unlocked_missing.insert(d.name.clone(), n);
            }
            Ok(state) => {
                if let Some(c) = chain_breach(&d.name, *state) {
                    breach(c);
                }
            }
            Err(u) => failed_reads.push(u),
        }
    }
    for (name, carrier) in &obs.carrier {
        if carrier.is_none() {
            breach(format!(
                "{name}: the device is gone (it is no longer in the link table)"
            ));
        }
    }
    for (label, present) in &obs.sockets {
        match present {
            Ok(true) => {}
            Ok(false) => breach(format!("{label} is missing from the classifier's XSKS map")),
            Err(u) => failed_reads.push(u),
        }
    }
    match &obs.rules {
        Ok(Ok(())) => {}
        Ok(Err(text)) => breach(text.clone()),
        Err(u) => failed_reads.push(u),
    }
    for d in &obs.devices {
        match &d.drops {
            Ok(Some(now)) => {
                if let Some(before) = prev.drops.get(&d.name)
                    && now > before
                {
                    breach(format!(
                        "{}: {} packets for our endpoints found no AF_XDP socket (classifier no-socket counter {before} -> {now})",
                        d.name,
                        now - before
                    ));
                }
                next.drops.insert(d.name.clone(), *now);
            }
            Ok(None) => {}
            Err(u) => {
                if let Some(before) = prev.drops.get(&d.name) {
                    next.drops.insert(d.name.clone(), *before);
                }
                failed_reads.push(u);
            }
        }
    }
    for t in &obs.tx {
        let key = format!("{} queue {}", t.device, t.queue);
        let up = obs
            .carrier
            .iter()
            .find(|(n, _)| *n == t.device)
            .is_none_or(|(_, c)| c.unwrap_or(false))
            && !obs.ineligible.contains(&t.device);
        let in_flight = t.submitted.wrapping_sub(t.completed);
        let track = match prev.tx.get(&key) {
            Some(p) if up && p.up && in_flight > 0 && p.completed == t.completed => {
                let waited = obs.now.saturating_duration_since(p.since);
                let mut tr = *p;
                if waited >= TX_STALL {
                    breach(format!(
                        "{key}: transmit stalled: {in_flight} frames in flight and no completion for {}s while the link is up",
                        waited.as_secs()
                    ));
                } else if waited >= TX_STALL / 2 && !p.kicked {
                    out.kick.push(Kick {
                        device: t.device.clone(),
                        queue: t.queue,
                        waited,
                    });
                    tr.kicked = true;
                }
                tr
            }
            _ => TxTrack {
                completed: t.completed,
                since: obs.now,
                up,
                kicked: false,
            },
        };
        next.tx.insert(key, track);
    }
    if let Err(u) = &obs.routing {
        failed_reads.push(u);
    }
    failed_reads.extend(&obs.bond);
    for u in failed_reads {
        let n = prev.unreadable.get(&u.what).copied().unwrap_or(0) + 1;
        if n >= UNREADABLE_PERIODS {
            breach(format!(
                "XDP health check: cannot read {} for {n} consecutive periods: {}",
                u.what, u.error
            ));
        }
        next.unreadable.insert(u.what.clone(), n);
    }
    out.cause = cause;
    (next, out)
}

pub(crate) fn is_transient(e: &(dyn Error + 'static)) -> bool {
    e.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) || matches!(e.raw_os_error(), Some(libc::EINTR | libc::EAGAIN))
    })
}

pub(crate) fn read_retrying<T>(
    deadline: Instant,
    abort: &dyn Fn() -> bool,
    mut f: impl FnMut() -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if is_transient(e.as_ref()) && Instant::now() < deadline && !abort() => {
                std::thread::sleep(READ_RETRY_STEP)
            }
            Err(e) => return Err(e),
        }
    }
}

pub(crate) struct AddrWatch {
    known: HashSet<(u32, Ipv4Addr)>,
}

impl AddrWatch {
    pub(crate) fn new(s: &Snapshot) -> Self {
        Self {
            known: s
                .addrs
                .iter()
                .filter(|(i, _)| s.xdp.contains(i))
                .copied()
                .collect(),
        }
    }

    pub(crate) fn added(&mut self, s: &Snapshot) -> Vec<AddrEvent> {
        let mut out = Vec::new();
        for (i, ip) in s.addrs.iter().filter(|(i, _)| s.xdp.contains(i)) {
            if self.known.insert((*i, *ip)) {
                out.push(AddrEvent::Added {
                    device: s.name(*i),
                    address: *ip,
                });
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AddrEvent {
    Added { device: String, address: Ipv4Addr },
}

fn log_addr(interface: &str, ev: &AddrEvent) {
    match ev {
        AddrEvent::Added { device, address } => tracing::warn!(
            interface = %interface,
            device = %device,
            address = %address,
            action = "restart",
            "XDP address added after start is not accelerated"
        ),
    }
}

pub(crate) struct MultipathWatch {
    known: HashSet<(Ipv4Addr, u8)>,
}

impl MultipathWatch {
    pub(crate) fn new() -> Self {
        Self {
            known: HashSet::new(),
        }
    }

    pub(crate) fn appeared(&mut self, s: &Snapshot) -> Vec<MultipathEvent> {
        s.multipath
            .iter()
            .copied()
            .filter(|m| self.known.insert(*m))
            .map(|prefix| MultipathEvent::Appeared {
                prefix,
                nexthop_object: s.is_nexthop_object(prefix),
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MultipathEvent {
    Appeared {
        prefix: (Ipv4Addr, u8),
        nexthop_object: bool,
    },
}

fn log_multipath(interface: &str, ev: &MultipathEvent) {
    let MultipathEvent::Appeared {
        prefix: (ip, len),
        nexthop_object,
    } = ev;
    let (route_kind, action) = if *nexthop_object {
        ("nexthop_object", "set nexthop_compat_mode=1")
    } else {
        ("multipath", "use a single next hop")
    };
    tracing::warn!(
        interface = %interface,
        prefix = %format_args!("{ip}/{len}"),
        route_kind,
        outcome = "dropped",
        reason = DropReason::NoNextHop.name(),
        action,
        "XDP route has no single next hop"
    );
}

pub(crate) struct GreWatch {
    known: HashSet<u32>,
}

impl GreWatch {
    pub(crate) fn new() -> Self {
        Self {
            known: HashSet::new(),
        }
    }

    pub(crate) fn appeared(&mut self, s: &Snapshot) -> Vec<GreEvent> {
        s.router
            .unusable_gre()
            .iter()
            .filter(|(i, _)| self.known.insert(*i))
            .map(|(i, reason)| GreEvent::Unusable {
                device: s.name(*i),
                ifindex: *i,
                reason,
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GreEvent {
    Unusable {
        device: String,
        ifindex: u32,
        reason: &'static str,
    },
}

fn log_gre(interface: &str, ev: &GreEvent) {
    let GreEvent::Unusable {
        device,
        ifindex,
        reason,
    } = ev;
    tracing::warn!(
        interface = %interface,
        device = %device,
        ifindex = *ifindex,
        state = "unavailable",
        reason = *reason,
        "XDP route GRE tunnel unusable"
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CarrierEvent {
    Changed { device: String, up: bool },
}

fn carrier_changes(
    prev: &Snapshot,
    next: &Snapshot,
    devices: &[(String, u32)],
) -> Vec<CarrierEvent> {
    devices
        .iter()
        .filter_map(|(name, i)| match (prev.carrier(*i), next.carrier(*i)) {
            (Some(a), Some(b)) if a != b => Some(CarrierEvent::Changed {
                device: name.clone(),
                up: b,
            }),
            _ => None,
        })
        .collect()
}

fn log_carrier(interface: &str, ev: &CarrierEvent) {
    let CarrierEvent::Changed { device, up } = ev;
    tracing::info!(
        interface = %interface,
        device = %device,
        state = if *up { "connected" } else { "disconnected" },
        "XDP device carrier changed"
    );
}

pub(crate) type UseNeighbor = Box<dyn FnMut(u32, Ipv4Addr) -> io::Result<()> + Send>;

pub(crate) fn kernel_use_neighbor() -> UseNeighbor {
    let mut sock: Option<NetlinkSocket> = None;
    Box::new(move |ifindex, ip| {
        let s = match sock.take() {
            Some(s) => s,
            None => NetlinkSocket::open()
                .map_err(|e| io::Error::other(format!("cannot open a netlink socket: {e}")))?,
        };
        netlink_use_neighbor(&s, ifindex, ip)?;
        sock = Some(s);
        Ok(())
    })
}

#[derive(Debug, Default)]
pub(crate) struct Retry {
    since: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryEvent {
    Failed,
    StillFailing,
    Recovered { downtime: Duration },
}

impl Retry {
    pub(crate) const fn failed(&mut self, now: Instant) -> RetryEvent {
        if self.since.is_none() {
            self.since = Some(now);
            RetryEvent::Failed
        } else {
            RetryEvent::StillFailing
        }
    }

    pub(crate) fn succeeded(&mut self, now: Instant) -> Option<RetryEvent> {
        self.since.take().map(|since| RetryEvent::Recovered {
            downtime: now.saturating_duration_since(since),
        })
    }

    pub(crate) const fn reset(&mut self) {
        self.since = None;
    }
}

pub(crate) struct Upkeep {
    used: HashMap<(u32, Ipv4Addr), Instant>,
    touched: HashMap<(u32, Ipv4Addr), Instant>,
    request: UseNeighbor,
    errors: u64,
    retry: Retry,
    failing: HashSet<(u32, Ipv4Addr)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpkeepEvent {
    pub retry: RetryEvent,
    pub failure: Option<(Ipv4Addr, u32, String)>,
    pub error_count: u64,
}

impl Upkeep {
    pub(crate) fn new(request: UseNeighbor) -> Self {
        Self {
            used: HashMap::new(),
            touched: HashMap::new(),
            request,
            errors: 0,
            retry: Retry::default(),
            failing: HashSet::new(),
        }
    }

    pub(crate) fn tick(
        &mut self,
        now: Instant,
        routes: &Routes,
        snap: &Snapshot,
    ) -> Option<UpkeepEvent> {
        for k in routes.take_marks() {
            self.used.insert(k, now);
        }
        if let Some((ip, i)) = snap.default_hop() {
            self.used.insert((i, ip), now);
        }
        self.used
            .retain(|_, t| now.saturating_duration_since(*t) < USED_WINDOW);
        let used = &self.used;
        self.touched.retain(|k, _| used.contains_key(k));
        let failing_before = !self.failing.is_empty();
        self.failing.retain(|k| used.contains_key(k));
        if failing_before && self.failing.is_empty() {
            self.retry.reset();
        }
        let mut failed: Option<(Ipv4Addr, u32, String)> = None;
        let mut refreshed = false;
        for &(ifindex, ip) in self.used.keys() {
            let (resolved, refresh) = match snap.resolve(ip) {
                Resolved::Xdp { refresh, .. } => (true, refresh),
                _ => (false, true),
            };
            if !refresh {
                continue;
            }
            let every = if resolved {
                USE_RESOLVED
            } else {
                USE_UNRESOLVED
            };
            if self
                .touched
                .get(&(ifindex, ip))
                .is_some_and(|t| now.saturating_duration_since(*t) < every)
            {
                continue;
            }
            match (self.request)(ifindex, ip) {
                Ok(()) => {
                    self.touched.insert((ifindex, ip), now);
                    self.failing.remove(&(ifindex, ip));
                    refreshed = true;
                }
                Err(e) => {
                    self.failing.insert((ifindex, ip));
                    failed = Some((ip, ifindex, e.to_string()));
                }
            }
        }
        if let Some(f) = failed {
            self.errors += 1;
            return Some(UpkeepEvent {
                retry: self.retry.failed(now),
                failure: Some(f),
                error_count: self.errors,
            });
        }
        if refreshed && self.failing.is_empty() {
            return self.retry.succeeded(now).map(|retry| UpkeepEvent {
                retry,
                failure: None,
                error_count: self.errors,
            });
        }
        None
    }
}

fn log_upkeep(interface: &str, ev: &UpkeepEvent) {
    let retry_delay_ms = HEALTH_PERIOD.as_millis();
    let (address, ifindex, error) = match &ev.failure {
        Some((a, i, e)) => (Some(a), Some(*i), Some(e)),
        None => (None, None, None),
    };
    let address = address.map(tracing::field::display);
    let error = error.map(tracing::field::display);
    match ev.retry {
        RetryEvent::Failed => tracing::warn!(
            interface = %interface,
            address,
            ifindex,
            operation = "refresh_neighbor",
            error,
            error_count = ev.error_count,
            action = "retry",
            retry_delay_ms,
            "XDP monitor neighbor refresh failed"
        ),
        RetryEvent::StillFailing => tracing::debug!(
            interface = %interface,
            address,
            ifindex,
            operation = "refresh_neighbor",
            error,
            error_count = ev.error_count,
            action = "retry",
            retry_delay_ms,
            "XDP monitor neighbor refresh still failing"
        ),
        RetryEvent::Recovered { downtime } => tracing::info!(
            interface = %interface,
            downtime_ms = downtime.as_millis(),
            state = "recovered",
            "XDP monitor neighbor refresh recovered"
        ),
    }
}

fn log_routing(
    interface: &str,
    what: Routing,
    ev: RetryEvent,
    error: Option<&dyn std::fmt::Display>,
) {
    let error = error.map(tracing::field::display);
    let retry_delay_ms = HEALTH_PERIOD.as_millis();
    match (what, ev) {
        (Routing::Tables, RetryEvent::Failed) => tracing::warn!(
            interface = %interface,
            operation = "read_routing_tables",
            error,
            action = "retry",
            retry_delay_ms,
            "XDP monitor routing refresh failed"
        ),
        (Routing::Tables, RetryEvent::StillFailing) => tracing::debug!(
            interface = %interface,
            operation = "read_routing_tables",
            error,
            action = "retry",
            retry_delay_ms,
            "XDP monitor routing refresh still failing"
        ),
        (Routing::Tables, RetryEvent::Recovered { downtime }) => tracing::info!(
            interface = %interface,
            downtime_ms = downtime.as_millis(),
            state = "recovered",
            "XDP monitor routing refresh recovered"
        ),
        (Routing::Events, RetryEvent::Failed) => tracing::warn!(
            interface = %interface,
            operation = "read_routing_events",
            error,
            action = "retry",
            "XDP monitor routing events failed"
        ),
        (Routing::Events, RetryEvent::StillFailing) => tracing::debug!(
            interface = %interface,
            operation = "read_routing_events",
            error,
            action = "retry",
            "XDP monitor routing events still failing"
        ),
        (Routing::Events, RetryEvent::Recovered { downtime }) => tracing::info!(
            interface = %interface,
            downtime_ms = downtime.as_millis(),
            state = "recovered",
            "XDP monitor routing events recovered"
        ),
    }
}

#[derive(Clone, Copy, Debug)]
enum Routing {
    Tables,
    Events,
}

pub(crate) const BOND_PERIOD: Duration = Duration::from_millis(250);
const BOND_WARN_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Managed {
    pub name: String,
    pub ifindex: u32,
    pub slave: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct BondState {
    pub managed: Vec<Managed>,
    pub mask: u64,
    pub errors: Vec<Unread>,
    failing: HashMap<String, (Instant, Instant)>,
}

impl BondState {
    pub(crate) fn new(managed: Vec<Managed>, mask: u64) -> Self {
        Self {
            managed,
            mask,
            errors: Vec::new(),
            failing: HashMap::new(),
        }
    }

    pub(crate) fn note_failing(&mut self, path: &str, now: Instant) {
        self.failing.insert(path.to_string(), (now, now));
    }

    pub(crate) fn ineligible(&self) -> Vec<String> {
        self.managed
            .iter()
            .filter(|m| m.slave >= 64 || self.mask & (1u64 << m.slave) == 0)
            .map(|m| m.name.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BondObs {
    pub members: Result<Vec<(String, u32)>, ReadError>,
    pub active: Result<String, ReadError>,
    pub states: Vec<(usize, Result<SlaveState, ReadError>)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BondOutcome {
    pub retire: Vec<Managed>,
    pub fail: Option<String>,
    pub publish: Option<u64>,
    pub events: Vec<BondEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BondEvent {
    Left {
        device: String,
        ifindex: u32,
        retired: bool,
    },
    Eligible {
        device: String,
    },
    NotEligible {
        device: String,
        reason: Ineligible,
    },
    ReadFailed {
        path: String,
        error: String,
    },
    ReadStillFailing {
        path: String,
        error: String,
    },
    ReadRecovered {
        path: String,
        downtime: Duration,
    },
}

pub(crate) fn log_bond(bond: &str, ev: &BondEvent) {
    match ev {
        BondEvent::Left {
            device,
            ifindex,
            retired: true,
        } => tracing::info!(
            bond = %bond,
            device = %device,
            ifindex = *ifindex,
            state = "disconnected",
            action = "retire",
            "XDP bond slave left the bond"
        ),
        BondEvent::Left {
            device,
            ifindex,
            retired: false,
        } => tracing::info!(
            bond = %bond,
            device = %device,
            ifindex = *ifindex,
            state = "disconnected",
            reason = "context failing",
            action = "none",
            "XDP bond slave left the bond"
        ),
        BondEvent::Eligible { device } => {
            tracing::info!(bond = %bond, device = %device, state = "ready", "XDP bond slave eligibility changed");
        }
        BondEvent::NotEligible { device, reason } => {
            let (port_state, aggregator, active_aggregator) = match reason {
                Ineligible::NotDistributing { port_state } => (Some(*port_state), None, None),
                Ineligible::AggregatorMismatch { aggregator, active } => {
                    (None, Some(aggregator), Some(active))
                }
                _ => (None, None, None),
            };
            let port_text = match reason {
                Ineligible::BadPortState { text } => Some(text),
                _ => None,
            };
            tracing::info!(
                bond = %bond,
                device = %device,
                state = "degraded",
                reason = reason.reason(),
                port_state,
                port_state_text = port_text.map(tracing::field::display),
                aggregator = aggregator.map(tracing::field::display),
                active_aggregator = active_aggregator.map(tracing::field::display),
                "XDP bond slave eligibility changed"
            );
        }
        BondEvent::ReadFailed { path, error } => tracing::warn!(
            bond = %bond,
            path = %path,
            operation = "read_sysfs",
            error = %error,
            state = "degraded",
            action = "retry",
            retry_delay_ms = BOND_PERIOD.as_millis(),
            "XDP bond sysfs read failed"
        ),
        BondEvent::ReadStillFailing { path, error } => tracing::debug!(
            bond = %bond,
            path = %path,
            operation = "read_sysfs",
            error = %error,
            state = "degraded",
            action = "retry",
            retry_delay_ms = BOND_PERIOD.as_millis(),
            "XDP bond sysfs read still failing"
        ),
        BondEvent::ReadRecovered { path, downtime } => tracing::info!(
            bond = %bond,
            path = %path,
            downtime_ms = downtime.as_millis(),
            state = "recovered",
            "XDP bond sysfs read recovered"
        ),
    }
}

pub(crate) fn read_bond(root: &SysfsRoot, bond: &str, st: &BondState) -> BondObs {
    let members = root.members(bond);
    let active = root.active_aggregator(bond);
    let states = st
        .managed
        .iter()
        .filter(|m| {
            members.as_ref().map_or(true, |c| {
                c.iter().any(|(n, i)| *n == m.name && *i == m.ifindex)
            })
        })
        .map(|m| (m.slave, root.slave_state(&m.name)))
        .collect();
    BondObs {
        members,
        active,
        states,
    }
}

pub(crate) fn bond_step(
    bond: &str,
    prev: &BondState,
    obs: &BondObs,
    now: Instant,
) -> (BondState, BondOutcome) {
    let mut out = BondOutcome::default();
    let mut managed = prev.managed.clone();
    let mut errors: Vec<ReadError> = Vec::new();
    let note = |e: &ReadError, errors: &mut Vec<ReadError>| {
        if !errors.iter().any(|x| x.path == e.path) {
            errors.push(e.clone());
        }
    };
    match &obs.members {
        Ok(current) => {
            let now_managed: Vec<(String, u32)> = managed
                .iter()
                .map(|m| (m.name.clone(), m.ifindex))
                .collect();
            for ev in membership_diff(&now_managed, current) {
                match ev {
                    MembershipEvent::Retired { name, ifindex } => {
                        if let Some(p) = managed
                            .iter()
                            .position(|m| m.name == name && m.ifindex == ifindex)
                        {
                            out.retire.push(managed.remove(p));
                        }
                    }
                    MembershipEvent::Added { name, .. } => {
                        if out.fail.is_none() {
                            out.fail = Some(format!(
                                "bond membership changed: {name} added to {bond}; restart to use it"
                            ));
                        }
                    }
                }
            }
        }
        Err(e) => note(e, &mut errors),
    }
    let mut read_slaves: Vec<&str> = Vec::new();
    if managed.is_empty() && !prev.managed.is_empty() && out.fail.is_none() {
        out.fail = Some(format!(
            "bond {bond} has no slave left; restart after slaves are back"
        ));
    }
    let mut mask = 0u64;
    let mut changes = Vec::new();
    for m in &managed {
        let verdict = match obs.states.iter().find(|(s, _)| *s == m.slave) {
            Some((_, st)) => judge(obs.active.as_ref(), st.clone()),
            None => Err(Ineligible::NotRead),
        };
        let bit = if m.slave < 64 { 1u64 << m.slave } else { 0 };
        if verdict.is_ok() {
            mask |= bit;
        }
        if obs.states.iter().any(|(s, _)| *s == m.slave) {
            read_slaves.push(&m.name);
        }
        if let Err(Ineligible::Unreadable(e)) = &verdict {
            note(e, &mut errors);
        }
        let was = prev.mask & bit != 0;
        match &verdict {
            Ok(()) if !was => changes.push(BondEvent::Eligible {
                device: m.name.clone(),
            }),
            Err(Ineligible::Unreadable(_)) => {}
            Err(reason) if was => changes.push(BondEvent::NotEligible {
                device: m.name.clone(),
                reason: reason.clone(),
            }),
            _ => {}
        }
    }
    let mut failing = HashMap::new();
    let mut warns = Vec::new();
    for e in &errors {
        match prev.failing.get(&e.path) {
            None => {
                warns.push(BondEvent::ReadFailed {
                    path: e.path.clone(),
                    error: e.error.clone(),
                });
                failing.insert(e.path.clone(), (now, now));
            }
            Some(&(since, noted)) if now.saturating_duration_since(noted) >= BOND_WARN_EVERY => {
                warns.push(BondEvent::ReadStillFailing {
                    path: e.path.clone(),
                    error: e.error.clone(),
                });
                failing.insert(e.path.clone(), (since, now));
            }
            Some(&f) => {
                failing.insert(e.path.clone(), f);
            }
        }
    }
    let still_read = |path: &str| {
        let slave_file = prev.managed.iter().find(|m| path_of(path, &m.name));
        slave_file.is_none_or(|m| read_slaves.contains(&m.name.as_str()))
    };
    let mut recovered: Vec<(&String, Instant)> = prev
        .failing
        .iter()
        .filter(|(p, _)| !failing.contains_key(*p) && still_read(p))
        .map(|(p, (since, _))| (p, *since))
        .collect();
    recovered.sort();
    warns.extend(
        recovered
            .into_iter()
            .map(|(path, since)| BondEvent::ReadRecovered {
                path: path.clone(),
                downtime: now.saturating_duration_since(since),
            }),
    );
    if mask != prev.mask {
        out.publish = Some(mask);
    }
    let retired = out.fail.is_none();
    out.events = out
        .retire
        .iter()
        .map(|m| BondEvent::Left {
            device: m.name.clone(),
            ifindex: m.ifindex,
            retired,
        })
        .chain(changes)
        .chain(warns)
        .collect();
    let next = BondState {
        managed,
        mask,
        errors: errors
            .into_iter()
            .map(|e| Unread {
                what: e.path,
                error: e.error,
            })
            .collect(),
        failing,
    };
    (next, out)
}

fn path_of(path: &str, dev: &str) -> bool {
    path.split('/').any(|c| c == dev)
}

pub(crate) struct BondParts {
    pub name: String,
    pub root: SysfsRoot,
    pub state: BondState,
    pub elig: Arc<Eligibility>,
    pub retire: Box<dyn FnMut(usize) + Send>,
    pub pending: Box<dyn FnMut() + Send>,
}

fn bond_tick(b: &mut BondParts, hub: &Hub, devices: &mut Vec<(String, u32)>, now: Instant) {
    let obs = read_bond(&b.root, &b.name, &b.state);
    let (next, out) = bond_step(&b.name, &b.state, &obs, now);
    b.state = next;
    for ev in &out.events {
        log_bond(&b.name, ev);
    }
    if let Some(m) = out.publish {
        b.elig.publish(m);
        hub.eligibility_changed();
    }
    if let Some(cause) = out.fail {
        if hub.check().is_ok() {
            hub.fail(cause);
        }
        return;
    }
    for m in out.retire {
        devices.retain(|(n, i)| !(*n == m.name && *i == m.ifindex));
        if hub.check().is_err() {
            return;
        }
        (b.retire)(m.slave);
    }
    (b.pending)();
}

pub(crate) type Observe = Box<dyn FnMut(Instant) -> Option<Observation> + Send>;

pub(crate) struct MonitorParts {
    pub hub: Arc<Hub>,
    pub routes: Arc<Routes>,
    pub events: NetlinkSocket,
    pub xdp: Vec<u32>,
    pub devices: Vec<(String, u32)>,
    pub observe: Observe,
    pub use_neighbor: UseNeighbor,
    pub bond: Option<BondParts>,
}

pub(crate) const EVENT_GROUPS: u32 =
    (libc::RTMGRP_IPV4_ROUTE | libc::RTMGRP_NEIGH | libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR)
        as u32;

pub(crate) struct Monitor {
    interface: String,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Monitor {
    pub(crate) fn start(parts: MonitorParts) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let interface = parts.routes.interface.clone();
        let handle = std::thread::Builder::new()
            .name("gun-xdp-monitor".into())
            .spawn(move || {
                let hub = Arc::clone(&parts.hub);
                let run =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(parts, &flag)));
                if run.is_err() {
                    hub.fail("XDP monitor thread panicked".into());
                }
            })?;
        Ok(Self {
            interface,
            stop,
            thread: Mutex::new(Some(handle)),
        })
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.thread.lock().take() else {
            return;
        };
        if handle.thread().id() == std::thread::current().id() {
            return;
        }
        let deadline = Instant::now() + MONITOR_JOIN;
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        if handle.is_finished() {
            if handle.join().is_err() {
                tracing::error!(interface = %self.interface, state = "failed", reason = "panicked", "XDP monitor stopped");
            }
        } else {
            tracing::error!(
                interface = %self.interface,
                wait_ms = MONITOR_JOIN.as_millis(),
                reason = "join timed out",
                action = "leave running",
                "XDP monitor did not stop"
            );
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_events(sock: &NetlinkSocket, wait: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(wait.as_millis().max(1)).unwrap_or(i32::MAX);
    let rc = unsafe { libc::poll(&raw mut pfd, 1, ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(e)
        };
    }
    if rc == 0 {
        return Ok(false);
    }
    let mut any = pfd.revents & libc::POLLERR != 0;
    loop {
        match sock.recv_nonblocking() {
            Ok(Some(_)) => any = true,
            Ok(None) => return Ok(any),
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => return Ok(true),
            Err(e) => return Err(e),
        }
    }
}

fn run(mut p: MonitorParts, stop: &AtomicBool) {
    let interface = p.routes.interface.clone();
    tracing::debug!(interface = %interface, state = "ready", "XDP monitor started");
    let mut snap = p.routes.snapshot();
    let mut addrs = AddrWatch::new(&snap);
    let mut multipath = MultipathWatch::new();
    for ev in multipath.appeared(&snap) {
        log_multipath(&interface, &ev);
    }
    let mut gre = GreWatch::new();
    for ev in gre.appeared(&snap) {
        log_gre(&interface, &ev);
    }
    let mut health = HealthState::default();
    let mut upkeep = Upkeep::new(p.use_neighbor);
    let mut events = Some(p.events);
    let mut dirty = false;
    let mut route_err: Option<String> = None;
    let mut events_retry = Retry::default();
    let mut tables_retry = Retry::default();
    let mut rebuild_at = Instant::now();
    let mut next_tick = Instant::now() + HEALTH_PERIOD;
    let mut bond = p.bond.take();
    let mut bond_at = Instant::now() + BOND_PERIOD;
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        let mut wait = next_tick.saturating_duration_since(now).min(POLL_STEP);
        if dirty {
            wait = wait.min(rebuild_at.saturating_duration_since(now));
        }
        if bond.is_some() {
            wait = wait.min(bond_at.saturating_duration_since(now));
        }
        match &events {
            Some(sock) => match wait_events(sock, wait) {
                Ok(any) => {
                    dirty |= any;
                    if let Some(ev) = events_retry.succeeded(Instant::now()) {
                        log_routing(&interface, Routing::Events, ev, None);
                    }
                }
                Err(e) => {
                    let ev = events_retry.failed(Instant::now());
                    log_routing(&interface, Routing::Events, ev, Some(&e));
                    events = None;
                    dirty = true;
                }
            },
            None => {
                std::thread::sleep(wait);
                match NetlinkSocket::bind(EVENT_GROUPS) {
                    Ok(s) => events = Some(s),
                    Err(e) => route_err = Some(format!("cannot subscribe to routing events: {e}")),
                }
                dirty = true;
            }
        }
        let now = Instant::now();
        let mut rebuilt = false;
        if dirty && now >= rebuild_at {
            match build_snapshot(&p.xdp) {
                Ok(next) => {
                    for ev in carrier_changes(&snap, &next, &p.devices) {
                        log_carrier(&interface, &ev);
                        let CarrierEvent::Changed { device, up } = ev;
                        if up {
                            p.hub.kick_device(&device);
                        }
                    }
                    for ev in multipath.appeared(&next) {
                        log_multipath(&interface, &ev);
                    }
                    for ev in addrs.added(&next) {
                        log_addr(&interface, &ev);
                    }
                    for ev in gre.appeared(&next) {
                        log_gre(&interface, &ev);
                    }
                    if let Some(ev) = tables_retry.succeeded(now) {
                        log_routing(&interface, Routing::Tables, ev, None);
                    }
                    p.routes.publish(next);
                    snap = p.routes.snapshot();
                    dirty = false;
                    rebuilt = true;
                    if events.is_some() {
                        route_err = None;
                    }
                    rebuild_at = now + REBUILD_GAP;
                }
                Err(e) => {
                    p.routes.refresh_errors.fetch_add(1, Ordering::Relaxed);
                    let ev = tables_retry.failed(now);
                    log_routing(&interface, Routing::Tables, ev, Some(&e));
                    route_err = Some(e.to_string());
                    rebuild_at = now + HEALTH_PERIOD;
                }
            }
        }
        let now = Instant::now();
        if let Some(b) = bond.as_mut()
            && (rebuilt || now >= bond_at || now >= next_tick)
            && p.hub.check().is_ok()
        {
            bond_at = now + BOND_PERIOD;
            bond_tick(b, &p.hub, &mut p.devices, now);
        }
        if Instant::now() < next_tick {
            continue;
        }
        let now = Instant::now();
        next_tick = now + HEALTH_PERIOD;
        if let Some(ev) = upkeep.tick(now, &p.routes, &snap) {
            log_upkeep(&interface, &ev);
        }
        if p.hub.check().is_err() {
            continue;
        }
        let Some(mut obs) = (p.observe)(now + HEALTH_PERIOD / 2) else {
            continue;
        };
        obs.carrier = p
            .devices
            .iter()
            .map(|(n, i)| (n.clone(), snap.carrier(*i)))
            .collect();
        obs.routing = match &route_err {
            None => Ok(()),
            Some(e) => Err(Unread {
                what: "the routing and neighbor tables".into(),
                error: e.clone(),
            }),
        };
        if let Some(b) = &bond {
            obs.bond = b.state.errors.clone();
            obs.ineligible = b.state.ineligible();
        }
        let (h, out) = evaluate(&health, &obs);
        health = h;
        for ev in &out.events {
            log_health(&interface, ev);
        }
        for k in out.kick {
            log_kick(&interface, &k);
            p.hub.kick_queue(&k.device, k.queue);
        }
        if let Some(c) = out.cause
            && p.hub.check().is_ok()
        {
            p.hub.fail(c);
        }
    }
    let reason = if p.hub.failed().is_some() {
        "context failed"
    } else {
        "shutdown"
    };
    tracing::debug!(interface = %interface, state = "stopped", reason, "XDP monitor stopped");
}
