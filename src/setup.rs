
use {
    crate::{
        classifier::{Classifier, Miss, owned_key},
        error::XdpError,
        installer::{self, EndpointPlan, Layout, RecordStore},
        nic::{InstalledRule, NicOps},
        pace::{self, Pace},
        record::{self, Owner},
        settings::{EndpointSpec, XdpMode, XdpSettings},
        bond,
        device::{NetworkDevice, QueueId},
        dispatcher::{self, BPFFS_XDP_DIR, BpffsLock, Dispatcher},
        netlink,
        socket::{Rx, Socket, Tx},
        umem::{OwnedUmem, OwnedUmemFrame, PageAlignedMemory},
    },
    std::{
        fs, io,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
        os::fd::{AsFd, AsRawFd},
        path::Path,
        time::Instant,
    },
};

pub(crate) const FRAME_SIZE: u32 = 4096;
pub(crate) const RX_RING: usize = 2048;
pub(crate) const TX_RING: usize = 2048;
pub(crate) const FRAMES_PER_SOCKET: usize = RX_RING + TX_RING;
pub(crate) const POOL_BYTES: u64 = FRAMES_PER_SOCKET as u64 * FRAME_SIZE as u64;

pub(crate) const REQUIRED_CAPS: [&str; 5] = [
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_BPF",
    "CAP_PERFMON",
    "CAP_SYS_ADMIN",
];

pub(crate) fn setup_err(
    interface: &str,
    device: Option<&str>,
    endpoint: Option<&str>,
    reason: impl Into<String>,
    remedy: impl Into<String>,
) -> XdpError {
    XdpError::Setup {
        interface: interface.to_string(),
        device: device.map(str::to_string),
        endpoint: endpoint.map(str::to_string),
        reason: reason.into(),
        remedy: remedy.into(),
    }
}

pub(crate) fn with_rollback_errors(
    e: XdpError,
    interface: &str,
    undo_errors: &[impl std::fmt::Display],
) -> XdpError {
    if undo_errors.is_empty() {
        return e;
    }
    let all: Vec<String> = undo_errors.iter().map(ToString::to_string).collect();
    let tail = format!("; rollback also failed: {}", all.join("; "));
    match e {
        XdpError::Setup {
            interface,
            device,
            endpoint,
            reason,
            remedy,
        } => XdpError::Setup {
            interface,
            device,
            endpoint,
            reason: format!("{reason}{tail}"),
            remedy,
        },
        other => XdpError::Setup {
            interface: interface.to_string(),
            device: None,
            endpoint: None,
            reason: format!("{other}{tail}"),
            remedy: "restart to retry; the next start removes what is left".into(),
        },
    }
}

pub(crate) fn check_settings(interface: &str, s: &XdpSettings) -> Result<(), XdpError> {
    if s.zero_copy && s.mode == XdpMode::Skb {
        return Err(setup_err(
            interface,
            None,
            None,
            "zero-copy was asked for in skb (generic) mode, which Linux does not offer",
            "set the XDP mode to drv or turn zero-copy off",
        ));
    }
    Ok(())
}

pub(crate) fn check_caps(interface: &str, missing: &[&str]) -> Result<(), XdpError> {
    if missing.is_empty() {
        return Ok(());
    }
    let all = REQUIRED_CAPS.join(" ");
    Err(setup_err(
        interface,
        None,
        None,
        format!("the process lacks {}", missing.join(", ")),
        format!(
            "grant all of {all}: `AmbientCapabilities={all}` (and the same in \
             `CapabilityBoundingSet=`) in the systemd unit, `--cap-add` for each in docker, or \
             `setcap` on the binary"
        ),
    ))
}

pub(crate) fn check_memlock(
    interface: &str,
    sockets: usize,
    limit: Option<u64>,
    ipc_lock: bool,
) -> Result<u64, XdpError> {
    let needed = POOL_BYTES.saturating_mul(sockets as u64);
    match limit {
        Some(limit) if !ipc_lock && needed > limit => Err(setup_err(
            interface,
            None,
            None,
            format!(
                "the AF_XDP frame pools need {needed} bytes of locked memory ({sockets} socket(s) \
                 x {POOL_BYTES} bytes) but RLIMIT_MEMLOCK is {limit} bytes and the process lacks \
                 CAP_IPC_LOCK (the limit counts per user, across all its processes)"
            ),
            format!(
                "raise the limit to at least {needed} bytes: `LimitMEMLOCK=infinity` in the \
                 systemd unit, `ulimit -l unlimited` in the shell that starts it, \
                 `--ulimit memlock=-1` in docker; or grant CAP_IPC_LOCK"
            ),
        )),
        _ => Ok(needed),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LinkKind {
    Physical,
    Veth,
    Bond { mode: String, slaves: Vec<String> },
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkFacts {
    pub name: String,
    pub kind: LinkKind,
}

pub(crate) const MAX_SLAVES: usize = 64;

pub(crate) fn resolve_devices(
    iface: &LinkFacts,
    native_bond: bool,
    slave: &mut dyn FnMut(&str) -> Result<LinkFacts, XdpError>,
) -> Result<Vec<String>, XdpError> {
    let name = iface.name.as_str();
    let refuse = |dev: &str, what: &str| {
        setup_err(
            name,
            (dev != name).then_some(dev),
            None,
            format!(
                "{dev} is {what}; XDP is supported on physical NICs, 802.3ad bonds of them and veth (tests), untagged only"
            ),
            "name a physical interface or an 802.3ad bond as the XDP interface",
        )
    };
    match (&iface.kind, native_bond) {
        (LinkKind::Bond { .. }, false) => Err(setup_err(
            name,
            None,
            None,
            format!("{name} is a bond but native bond mode is off"),
            "turn native bond mode on (802.3ad bonds only) or name a single physical interface",
        )),
        (LinkKind::Bond { mode, slaves }, true) => {
            if mode != "802.3ad" {
                return Err(setup_err(
                    name,
                    None,
                    None,
                    format!("bond {name} is in mode {mode}; only 802.3ad is supported"),
                    "switch the bond to 802.3ad (LACP) or turn XDP off",
                ));
            }
            if slaves.is_empty() {
                return Err(setup_err(
                    name,
                    None,
                    None,
                    format!("bond {name} has no slave"),
                    "enslave at least one interface before starting",
                ));
            }
            if slaves.len() > MAX_SLAVES {
                return Err(setup_err(
                    name,
                    None,
                    None,
                    format!(
                        "bond {name} has {} slaves; at most {MAX_SLAVES} are supported (one bit each in the eligibility mask)",
                        slaves.len()
                    ),
                    format!("use a bond of at most {MAX_SLAVES} slaves"),
                ));
            }
            for s in slaves {
                match slave(s)?.kind {
                    LinkKind::Physical | LinkKind::Veth => {}
                    LinkKind::Bond { .. } => return Err(refuse(s, "a bond inside a bond")),
                    LinkKind::Other(kind) => return Err(refuse(s, &format!("a {kind} interface"))),
                }
            }
            Ok(slaves.clone())
        }
        (_, true) => Err(setup_err(
            name,
            None,
            None,
            format!("{name} is not a bond, but native bond mode is on"),
            "turn native bond mode off, or name the 802.3ad bond as the XDP interface",
        )),
        (LinkKind::Physical | LinkKind::Veth, false) => Ok(vec![name.to_string()]),
        (LinkKind::Other(kind), false) => Err(refuse(name, &format!("a {kind} interface"))),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Expanded {
    pub name: &'static str,
    pub listen: SocketAddrV4,
    pub addrs: Vec<Ipv4Addr>,
}

pub(crate) fn expand(
    interface: &str,
    specs: &[EndpointSpec],
    iface_addrs: &[Ipv4Addr],
) -> Result<Vec<Expanded>, XdpError> {
    if specs.is_empty() {
        return Err(setup_err(
            interface,
            None,
            None,
            "no endpoints were given to accelerate",
            "pass the endpoints to the context, or turn XDP off",
        ));
    }
    let have = || {
        if iface_addrs.is_empty() {
            "none".to_string()
        } else {
            iface_addrs
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let mut out: Vec<Expanded> = Vec::with_capacity(specs.len());
    for spec in specs {
        if out.iter().any(|e| e.name == spec.name) {
            return Err(setup_err(
                interface,
                None,
                Some(spec.name),
                format!("endpoint name {} is given twice", spec.name),
                "give every endpoint its own name",
            ));
        }
        let ip = *spec.listen.ip();
        let addrs = if ip.is_unspecified() {
            if iface_addrs.is_empty() {
                return Err(setup_err(
                    interface,
                    None,
                    Some(spec.name),
                    format!(
                        "{interface} has no IPv4 address to listen on for {}",
                        spec.listen
                    ),
                    "assign an IPv4 address to the interface before starting",
                ));
            }
            iface_addrs.to_vec()
        } else if iface_addrs.contains(&ip) {
            vec![ip]
        } else {
            return Err(setup_err(
                interface,
                None,
                Some(spec.name),
                format!(
                    "{ip} is not an IPv4 address of {interface} (it has {})",
                    have()
                ),
                format!(
                    "listen on one of {interface}'s addresses or 0.0.0.0, or add {ip} to it before starting"
                ),
            ));
        };
        let port = spec.listen.port();
        if port != 0
            && let Some((other, addr)) = out.iter().find_map(|e| {
                (e.listen.port() == port)
                    .then(|| {
                        e.addrs
                            .iter()
                            .find(|a| addrs.contains(a))
                            .map(|a| (e.name, *a))
                    })
                    .flatten()
            })
        {
            return Err(setup_err(
                interface,
                None,
                Some(spec.name),
                format!(
                    "endpoints {other} and {} both listen on {addr}:{port}",
                    spec.name
                ),
                "give each endpoint its own address or port",
            ));
        }
        out.push(Expanded {
            name: spec.name,
            listen: spec.listen,
            addrs,
        });
    }
    Ok(out)
}

pub(crate) fn check_owned_capacity(interface: &str, eps: &[Expanded]) -> Result<(), XdpError> {
    let cap = crate::classifier::OWNED_CAPACITY;
    let keys: usize = eps.iter().map(|e| e.addrs.len()).sum();
    if keys <= cap {
        return Ok(());
    }
    let per: Vec<String> = eps
        .iter()
        .map(|e| format!("{} {}", e.name, e.addrs.len()))
        .collect();
    Err(setup_err(
        interface,
        None,
        None,
        format!(
            "the endpoints need {keys} classifier keys (one per address and port: {}), and the classifier's \
             OWNED map holds {cap}",
            per.join(", ")
        ),
        "listen on specific addresses instead of 0.0.0.0, or accelerate fewer endpoints",
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayoutKind {
    Dedicated,
    Shared,
}

impl LayoutKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Shared => "shared",
        }
    }
}

pub(crate) fn layout_kind(
    interface: &str,
    layouts: &[(String, Layout)],
) -> Result<LayoutKind, XdpError> {
    let kind_of = |l: &Layout| match l {
        Layout::Dedicated { .. } => LayoutKind::Dedicated,
        Layout::Shared { .. } => LayoutKind::Shared,
    };
    let Some((first_dev, first)) = layouts.first() else {
        return Err(setup_err(
            interface,
            None,
            None,
            "no device to plan",
            "internal error: report this",
        ));
    };
    let kind = kind_of(first);
    for (dev, layout) in layouts {
        if kind_of(layout) != kind {
            return Err(setup_err(
                interface,
                Some(dev),
                None,
                format!(
                    "devices {first_dev} ({}) and {dev} ({}) need the same steering layout",
                    kind.name(),
                    kind_of(layout).name()
                ),
                "make ntuple filters available on every slave (`ethtool -K <dev> ntuple on`), or \
                 bond slaves of one NIC model",
            ));
        }
        let too_many = |what: String| {
            setup_err(
                interface,
                Some(dev),
                None,
                what,
                format!(
                    "at most {} receive queues are supported; use fewer channels (`ethtool -L {dev} combined <n>`)",
                    crate::classifier::MAX_QUEUES
                ),
            )
        };
        match layout {
            Layout::Dedicated { queues } => {
                if let Some(q) = queues.iter().find(|q| **q >= crate::classifier::MAX_QUEUES) {
                    return Err(too_many(format!(
                        "planned queue {q} is beyond the classifier's socket map"
                    )));
                }
            }
            Layout::Shared { queues } => {
                if *queues > crate::classifier::MAX_QUEUES {
                    return Err(too_many(format!("the device has {queues} receive queues")));
                }
            }
        }
    }
    Ok(kind)
}

pub(crate) fn assign_slots(
    interface: &str,
    endpoints: usize,
    kind: LayoutKind,
) -> Result<Vec<u32>, XdpError> {
    match kind {
        LayoutKind::Shared => Ok(vec![0; endpoints]),
        LayoutKind::Dedicated => {
            let max = crate::classifier::MAX_SLOTS;
            match u32::try_from(endpoints) {
                Ok(n) if n <= max => Ok((0..n).collect()),
                _ => Err(setup_err(
                    interface,
                    None,
                    None,
                    format!(
                        "{endpoints} endpoints need one classifier slot each, and there are {max}"
                    ),
                    format!("accelerate at most {max} endpoints"),
                )),
            }
        }
    }
}

pub(crate) fn socket_count(layouts: &[(String, Layout)]) -> usize {
    layouts
        .iter()
        .map(|(_, l)| match l {
            Layout::Dedicated { queues } => queues.len(),
            Layout::Shared { queues } => *queues as usize,
        })
        .sum()
}

pub(crate) const fn mode_name(mode: XdpMode) -> &'static str {
    match mode {
        XdpMode::Drv => "drv",
        XdpMode::Skb => "skb",
    }
}

pub(crate) struct Journal<C> {
    changes: Vec<C>,
    recorded: usize,
    #[allow(dead_code)]
    die_at: Option<usize>,
}

impl<C> Journal<C> {
    pub(crate) const fn new(die_at: Option<usize>) -> Self {
        Self {
            changes: Vec::new(),
            recorded: 0,
            die_at,
        }
    }

    pub(crate) fn record(&mut self, change: C) {
        self.changes.push(change);
        self.recorded += 1;
    }

    pub(crate) fn retain(&mut self, keep: impl FnMut(&C) -> bool) {
        self.changes.retain(keep);
    }

    pub(crate) const fn len(&self) -> usize {
        self.changes.len()
    }

    pub(crate) fn unwind<S, E>(
        &mut self,
        state: &mut S,
        undo: fn(&mut S, &C) -> Result<(), E>,
    ) -> Vec<E> {
        let mut errors = Vec::new();
        while let Some(change) = self.changes.pop() {
            if let Err(e) = undo(state, &change) {
                errors.push(e);
            }
        }
        errors
    }
}

pub(crate) type StepFn<S, C> = fn(&mut S, &mut Journal<C>) -> Result<(), XdpError>;

pub(crate) fn run_steps<S, C, E: std::fmt::Display>(
    interface: &str,
    state: &mut S,
    journal: &mut Journal<C>,
    steps: &[(&'static str, StepFn<S, C>)],
    undo: fn(&mut S, &C) -> Result<(), E>,
) -> Result<(), XdpError> {
    for (name, step) in steps {
        if let Err(e) = step(state, journal) {
            tracing::debug!(
                interface = %interface,
                operation = *name,
                error = %e,
                change_count = journal.len(),
                action = "roll back",
                "XDP context setup step failed"
            );
            let errors = journal.unwind(state, undo);
            return Err(with_rollback_errors(e, interface, &errors));
        }
    }
    Ok(())
}

fn dev_opt<'a>(interface: &str, device: &'a str) -> Option<&'a str> {
    (device != interface).then_some(device)
}

pub(crate) fn interface_name(settings: &XdpSettings) -> Result<String, XdpError> {
    match &settings.interface {
        Some(name) => Ok(name.clone()),
        None => NetworkDevice::new_from_default_route()
            .map(|d| d.name().to_string())
            .map_err(|e| {
                setup_err(
                    "(default route)",
                    None,
                    None,
                    format!("no XDP interface is configured and the default route's device cannot be found: {e}"),
                    "configure the XDP interface explicitly",
                )
            }),
    }
}

pub(crate) fn missing_caps(interface: &str) -> Result<Vec<&'static str>, XdpError> {
    missing_caps_of(interface, &REQUIRED_CAPS)
}

pub(crate) fn missing_caps_of(
    interface: &str,
    required: &[&'static str],
) -> Result<Vec<&'static str>, XdpError> {
    let mut missing = Vec::new();
    for &name in required {
        let cap: caps::Capability = name.parse().map_err(|e| {
            setup_err(
                interface,
                None,
                None,
                format!("unknown capability {name}: {e}"),
                "internal error: report this",
            )
        })?;
        let have = caps::has_cap(None, caps::CapSet::Effective, cap).map_err(|e| {
            setup_err(
                interface,
                None,
                None,
                format!("cannot read the process capabilities: {e}"),
                "check that /proc is mounted",
            )
        })?;
        if !have {
            missing.push(name);
        }
    }
    Ok(missing)
}

fn memlock_facts(interface: &str) -> Result<(Option<u64>, bool), XdpError> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } != 0 {
        return Err(setup_err(
            interface,
            None,
            None,
            format!("cannot read RLIMIT_MEMLOCK: {}", io::Error::last_os_error()),
            "internal error: report this",
        ));
    }
    let limit = (rl.rlim_cur != libc::RLIM_INFINITY).then_some(rl.rlim_cur);
    let ipc_lock = caps::has_cap(
        None,
        caps::CapSet::Effective,
        caps::Capability::CAP_IPC_LOCK,
    )
    .map_err(|e| {
        setup_err(
            interface,
            None,
            None,
            format!("cannot read the process capabilities: {e}"),
            "check that /proc is mounted",
        )
    })?;
    Ok((limit, ipc_lock))
}

fn link_facts(interface: &str, name: &str) -> Result<LinkFacts, XdpError> {
    let device = dev_opt(interface, name);
    let err = |what: String, remedy: &str| setup_err(interface, device, None, what, remedy);
    let dev = NetworkDevice::new(name).map_err(|e| {
        err(
            format!("interface {name} cannot be found: {e}"),
            "check the interface name (`ip link`)",
        )
    })?;
    let kind = netlink::link_kind(dev.if_index()).map_err(|e| {
        err(
            format!("cannot read the link kind of {name}: {e}"),
            "check that the process has CAP_NET_ADMIN",
        )
    })?;
    let kind = match kind.as_deref() {
        Some("veth") => LinkKind::Veth,
        Some("bond") => {
            let sysfs = "check that /sys is mounted and shows the bond";
            let mode = bond::mode(name)
                .map_err(|e| err(format!("cannot read the mode of bond {name}: {e}"), sysfs))?;
            let slaves = bond::slaves(name)
                .map_err(|e| err(format!("cannot read the slaves of bond {name}: {e}"), sysfs))?
                .ok_or_else(|| {
                    err(
                        format!("bond {name} has no bonding/slaves file in sysfs"),
                        sysfs,
                    )
                })?;
            LinkKind::Bond { mode, slaves }
        }
        Some(other) => LinkKind::Other(other.to_string()),
        None => match fs::symlink_metadata(format!("/sys/class/net/{name}/device")) {
            Ok(_) => LinkKind::Physical,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                LinkKind::Other("loopback or other virtual".to_string())
            }
            Err(e) => {
                return Err(err(
                    format!("cannot tell whether {name} is a physical device: {e}"),
                    "check that /sys is mounted",
                ));
            }
        },
    };
    Ok(LinkFacts {
        name: name.to_string(),
        kind,
    })
}

fn driver_name(interface: &str, dev: &NetworkDevice, kind: &LinkKind) -> Result<String, XdpError> {
    match (dev.driver(), kind) {
        (Ok(d), _) => Ok(d),
        (Err(_), LinkKind::Veth) => Ok("veth".to_string()),
        (Err(e), _) => Err(setup_err(
            interface,
            dev_opt(interface, dev.name()),
            None,
            format!("cannot read the driver of {}: {e}", dev.name()),
            "check that /sys is mounted and shows the device",
        )),
    }
}

pub(crate) fn interface_gone(ifindex: u32) -> io::Result<bool> {
    match NetworkDevice::new_from_index(ifindex) {
        Ok(_) => Ok(false),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) => Ok(true),
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub(crate) struct Plan {
    pub interface: String,
    pub mode: XdpMode,
    pub zero_copy: bool,
    pub bond: bool,
    pub kind: LayoutKind,
    pub devices: Vec<PlannedDevice>,
    pub endpoints: Vec<PlannedEndpoint>,
}

#[derive(Debug)]
pub(crate) struct PlannedDevice {
    pub name: String,
    pub ifindex: u32,
    pub driver: String,
    pub layout: Layout,
}

#[derive(Debug)]
pub(crate) struct PlannedEndpoint {
    pub name: &'static str,
    pub listen: SocketAddrV4,
    pub addrs: Vec<Ipv4Addr>,
    pub slot: u32,
}

impl PlannedDevice {
    pub(crate) fn sockets(&self, endpoints: &[PlannedEndpoint]) -> Vec<(u32, u32)> {
        match &self.layout {
            Layout::Shared { queues } => (0..*queues).map(|q| (0, q)).collect(),
            Layout::Dedicated { queues } => endpoints
                .iter()
                .filter_map(|e| queues.get(e.slot as usize).map(|q| (e.slot, *q)))
                .collect(),
        }
    }

    pub(crate) fn queues(&self) -> Vec<u32> {
        match &self.layout {
            Layout::Shared { queues } => (0..*queues).collect(),
            Layout::Dedicated { queues } => queues.clone(),
        }
    }
}

pub(crate) struct Prepared {
    pub plan: Plan,
    pub devices: Vec<NetworkDevice>,
}

pub(crate) fn prepare(
    settings: &XdpSettings,
    specs: &[EndpointSpec],
    interface: &str,
    nic: &dyn NicOps,
    lock: &BpffsLock,
) -> Result<Prepared, XdpError> {
    let iface = link_facts(interface, interface)?;
    let names = resolve_devices(&iface, settings.native_bond, &mut |n| {
        link_facts(interface, n)
    })?;
    let mut devices = Vec::with_capacity(names.len());
    let mut drivers = Vec::with_capacity(names.len());
    for name in &names {
        let facts = if *name == iface.name {
            iface.clone()
        } else {
            link_facts(interface, name)?
        };
        let dev = NetworkDevice::new(name.as_str()).map_err(|e| {
            setup_err(
                interface,
                dev_opt(interface, name),
                None,
                format!("{name} vanished: {e}"),
                "restart once the device is back",
            )
        })?;
        drivers.push(driver_name(interface, &dev, &facts.kind)?);
        devices.push(dev);
    }

    let ifindex = NetworkDevice::new(interface)
        .map_err(|e| {
            setup_err(
                interface,
                None,
                None,
                format!("{interface} vanished: {e}"),
                "restart once it is back",
            )
        })?
        .if_index();
    let addrs = netlink::ipv4_addrs(ifindex).map_err(|e| {
        setup_err(
            interface,
            None,
            None,
            format!("cannot list the IPv4 addresses of {interface}: {e}"),
            "check that the process has CAP_NET_ADMIN",
        )
    })?;
    let expanded = expand(interface, specs, &addrs)?;
    check_owned_capacity(interface, &expanded)?;

    let mut configured = vec![ifindex];
    configured.extend(devices.iter().map(NetworkDevice::if_index));
    reap_leftovers(interface, nic, lock, &configured)?;
    check_conflicts(interface, nic, lock, &devices, &expanded)?;

    let mut layouts = Vec::with_capacity(devices.len());
    for dev in &devices {
        layouts.push((
            dev.name().to_string(),
            installer::plan(nic, dev.name(), expanded.len())?,
        ));
    }
    if dedicated_forced() {
        if expanded.len() != 1 {
            return Err(setup_err(
                interface,
                None,
                None,
                "the forced dedicated layout takes one endpoint",
                "pass one endpoint",
            ));
        }
        for (_, l) in &mut layouts {
            *l = Layout::Dedicated { queues: vec![0] };
        }
    }
    let kind = layout_kind(interface, &layouts)?;
    let slots = assign_slots(interface, expanded.len(), kind)?;
    for (name, layout) in &layouts {
        if let Layout::Dedicated { queues } = layout
            && queues.len() != expanded.len()
        {
            return Err(setup_err(
                interface,
                dev_opt(interface, name),
                None,
                format!(
                    "planned {} queues for {} endpoints",
                    queues.len(),
                    expanded.len()
                ),
                "internal error: report this",
            ));
        }
    }

    let (limit, ipc_lock) = memlock_facts(interface)?;
    check_memlock(interface, socket_count(&layouts), limit, ipc_lock)?;

    let planned_devices = devices
        .iter()
        .zip(drivers)
        .zip(layouts)
        .map(|((dev, driver), (name, layout))| PlannedDevice {
            name,
            ifindex: dev.if_index(),
            driver,
            layout,
        })
        .collect();
    let endpoints = expanded
        .into_iter()
        .zip(slots)
        .map(|(e, slot)| PlannedEndpoint {
            name: e.name,
            listen: e.listen,
            addrs: e.addrs,
            slot,
        })
        .collect();
    Ok(Prepared {
        plan: Plan {
            interface: interface.to_string(),
            mode: settings.mode,
            zero_copy: settings.zero_copy,
            bond: settings.native_bond,
            kind,
            devices: planned_devices,
            endpoints,
        },
        devices,
    })
}

#[allow(unused_variables)]
#[allow(clippy::missing_const_for_fn)]
fn die_in_reap(point: u8) {
}

#[allow(clippy::missing_const_for_fn)]
fn dedicated_forced() -> bool {
    {
        false
    }
}

#[allow(clippy::missing_const_for_fn)]
pub(crate) fn die_at_from_env(interface: &str) -> Result<Option<usize>, XdpError> {
    {
        let _ = interface;
        Ok(None)
    }
}

fn reap_leftovers(
    interface: &str,
    nic: &dyn NicOps,
    lock: &BpffsLock,
    configured: &[u32],
) -> Result<(), XdpError> {
    for owner in record::dead_owners(Path::new(BPFFS_XDP_DIR), lock)? {
        let (dir, deleted) = reap_owner(interface, nic, owner)?;
        tracing::info!(
            interface = %interface,
            path = %dir,
            rule_count = deleted,
            outcome = "completed",
            "XDP context dead process leftovers removed"
        );
    }
    let (removed, warnings) = dispatcher::reap_dead_members_everywhere(lock, configured, &mut || die_in_reap(2)).map_err(|e| {
        setup_err(
            interface,
            None,
            None,
            format!("cannot remove dead XDP chain members of a previous run: {e}"),
            "if nothing else uses XDP on that interface, detach XDP from the interface named above (`ip link set dev NAME xdp off` with that name) and restart",
        )
    })?;
    for w in warnings {
        tracing::warn!(
            interface = %interface,
            device = w.device.as_ref().map(tracing::field::display),
            ifindex = w.ifindex,
            operation = "remove_dead_members",
            error = %w.error,
            reason = "not an interface of this context",
            action = "retry at the next start",
            "XDP context dead chain member cleanup failed"
        );
    }
    for r in &removed {
        let all: Vec<u32> = r.members.iter().chain(&r.markers).copied().collect();
        if all.is_empty() {
            continue;
        }
        let ids: Vec<String> = all.iter().map(u32::to_string).collect();
        tracing::info!(
            interface = %interface,
            ifindex = r.ifindex,
            member_ids = %ids.join(","),
            member_count = all.len(),
            outcome = "completed",
            "XDP context dead chain members removed"
        );
    }
    Ok(())
}

pub(crate) fn reap_owner(
    interface: &str,
    nic: &dyn NicOps,
    mut owner: Owner,
) -> Result<(String, usize), XdpError> {
    let dir = owner.dir().display().to_string();
    let read_err = |e: io::Error| {
        setup_err(
            interface,
            None,
            None,
            format!("cannot read the ownership record {dir} of a dead process: {e}"),
            "check the bpf filesystem; the record is kept and retried at the next start",
        )
    };
    for r in owner.all().map_err(read_err)? {
        let gone = interface_gone(r.ifindex).map_err(read_err)?;
        if gone {
            RecordStore::remove(&mut owner, &r).map_err(read_err)?;
        }
    }
    let deleted = installer::reap(nic, &mut owner)?;
    die_in_reap(1);
    owner.remove()?;
    Ok((dir, deleted))
}

fn check_conflicts(
    interface: &str,
    nic: &dyn NicOps,
    lock: &BpffsLock,
    devices: &[NetworkDevice],
    eps: &[Expanded],
) -> Result<(), XdpError> {
    let wanted: Vec<(&'static str, Ipv4Addr, u16, u64)> = eps
        .iter()
        .filter(|e| e.listen.port() != 0)
        .flat_map(|e| {
            let port = e.listen.port();
            e.addrs
                .iter()
                .map(move |a| (e.name, *a, port, owned_key(*a, port)))
        })
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let keys: Vec<u64> = wanted.iter().map(|w| w.3).collect();
    let remedy = "stop the other process, or give this endpoint another address or port";
    for dev in devices {
        let device = dev_opt(interface, dev.name());
        let inspect = |what: &str, e: &dyn std::fmt::Display| {
            setup_err(
                interface,
                device,
                None,
                format!("cannot {what} on {}: {e}", dev.name()),
                "check the process capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN)",
            )
        };
        let owned = dispatcher::owned_by_live_member(dev, &keys, lock)
            .map_err(|e| inspect("read the classifiers of the XDP chain", &e))?;
        if let Some((member, key)) = owned
            && let Some((name, ip, port, _)) = wanted.iter().find(|w| w.3 == key)
        {
            return Err(setup_err(
                interface,
                device,
                Some(name),
                format!(
                    "endpoint already accelerated by another process: {ip}:{port} is owned by the \
                     live XDP chain member {member} on {}",
                    dev.name()
                ),
                remedy,
            ));
        }
        if nic
            .supports_ntuple(dev.name())
            .map_err(|e| inspect("read the ntuple feature", &e))?
        {
            for rule in nic
                .rules(dev.name())
                .map_err(|e| inspect("read the steering rules", &e))?
            {
                let Some(spec) = rule.as_ours() else { continue };
                if let Some((name, ip, port, _)) = wanted
                    .iter()
                    .find(|w| w.1 == spec.dst_ip && w.2 == spec.dst_port)
                {
                    return Err(setup_err(
                        interface,
                        device,
                        Some(name),
                        format!(
                            "endpoint already accelerated by another process: the steering rule at \
                             location {} on {} sends {ip}:{port} to queue {}",
                            rule.location,
                            dev.name(),
                            spec.queue
                        ),
                        remedy,
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct BoundQueue {
    pub queue: u32,
    pub slot: u32,
    pub rx: Rx<OwnedUmemFrame>,
    pub tx: Tx<OwnedUmemFrame>,
    pub socket: Socket<OwnedUmem>,
}

unsafe impl Send for BoundQueue {}

pub(crate) struct DeviceRes {
    pub dev: NetworkDevice,
    pub dispatcher: Option<Dispatcher>,
    pub classifier: Option<Classifier>,
    pub rules: Vec<InstalledRule>,
    pub queues: Vec<Option<BoundQueue>>,
    pub drops_off: bool,
    pub retired: bool,
    pub retired_cores: Vec<(u32, crate::quic::socket::QueueCore)>,
}

pub(crate) struct Resources {
    pub reserved: Vec<Option<UdpSocket>>,
    pub ports: Vec<u16>,
    pub record: Option<Owner>,
    pub devices: Vec<DeviceRes>,
    pub armed: Vec<bool>,
    pub deferred: Vec<PendingLeave>,
    pub pace: Pace,
}

impl Resources {
    pub(crate) fn new(devices: Vec<NetworkDevice>, endpoints: &[PlannedEndpoint]) -> Self {
        Self {
            reserved: endpoints.iter().map(|_| None).collect(),
            ports: endpoints.iter().map(|e| e.listen.port()).collect(),
            record: None,
            devices: devices
                .into_iter()
                .map(|dev| DeviceRes {
                    dev,
                    dispatcher: None,
                    classifier: None,
                    rules: Vec::new(),
                    queues: Vec::new(),
                    drops_off: false,
                    retired: false,
                    retired_cores: Vec::new(),
                })
                .collect(),
            armed: vec![false; endpoints.len()],
            deferred: Vec::new(),
            pace: Pace::off(),
        }
    }

    pub(crate) fn paced_for(mut self, plan: &Plan) -> Self {
        let active = pace::needed(plan.bond, plan.mode == XdpMode::Drv, plan.devices.len());
        let slaves = plan.devices.iter().map(|d| d.name.clone()).collect();
        self.pace = Pace::for_bond(&plan.interface, slaves, active);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Reserved {
        endpoint: usize,
    },
    Record,
    Rules {
        device: usize,
    },
    Member {
        device: usize,
    },
    Socket {
        device: usize,
        index: usize,
        slot: u32,
        queue: u32,
    },
    Owned {
        device: usize,
        ip: Ipv4Addr,
        port: u16,
    },
}

pub(crate) struct Build<'a> {
    pub nic: &'a dyn NicOps,
    pub lock: Option<&'a BpffsLock>,
    pub plan: &'a Plan,
    pub res: &'a mut Resources,
}

pub(crate) fn steps<'a>() -> [(&'static str, StepFn<Build<'a>, Change>); 5] {
    [
        ("reserve_ports", reserve),
        ("create_record", create_record),
        ("install_rules", install_rules),
        ("join_chain", attach),
        ("bind_sockets", open_sockets),
    ]
}

pub(crate) fn internal(interface: &str, what: &str) -> XdpError {
    setup_err(
        interface,
        None,
        None,
        format!("internal error: {what}"),
        "report this",
    )
}

fn reserve(b: &mut Build<'_>, j: &mut Journal<Change>) -> Result<(), XdpError> {
    let interface = b.plan.interface.as_str();
    let mut order: Vec<usize> = (0..b.plan.endpoints.len()).collect();
    order.sort_by_key(|i| b.plan.endpoints[*i].listen.port() == 0);
    for i in order {
        let ep = &b.plan.endpoints[i];
        let fail = |what: String, e: &io::Error| {
            let remedy = if e.kind() == io::ErrorKind::AddrInUse {
                "another socket already uses this address and port; stop its owner or choose another port"
            } else {
                "check the listen address"
            };
            setup_err(
                interface,
                None,
                Some(ep.name),
                format!("{what}: {e}"),
                remedy,
            )
        };
        let sock = UdpSocket::bind(ep.listen).map_err(|e| {
            fail(
                format!(
                    "cannot bind the endpoint's kernel UDP socket to {}",
                    ep.listen
                ),
                &e,
            )
        })?;
        let port = match sock.local_addr() {
            Ok(SocketAddr::V4(a)) => a.port(),
            Ok(other) => {
                return Err(internal(
                    interface,
                    &format!("{} bound to {other}", ep.name),
                ));
            }
            Err(e) => return Err(fail("cannot read the reserved port".to_string(), &e)),
        };
        b.res.reserved[i] = Some(sock);
        b.res.ports[i] = port;
        j.record(Change::Reserved { endpoint: i });
    }
    Ok(())
}

fn create_record(b: &mut Build<'_>, j: &mut Journal<Change>) -> Result<(), XdpError> {
    let lock = b
        .lock
        .ok_or_else(|| internal(&b.plan.interface, "setup without the bpffs lock"))?;
    b.res.record = Some(Owner::create(Path::new(BPFFS_XDP_DIR), lock)?);
    j.record(Change::Record);
    Ok(())
}

fn install_rules(b: &mut Build<'_>, j: &mut Journal<Change>) -> Result<(), XdpError> {
    let eps: Vec<EndpointPlan> = b
        .plan
        .endpoints
        .iter()
        .zip(&b.res.ports)
        .map(|(e, port)| EndpointPlan {
            name: e.name,
            slot: e.slot,
            addrs: e.addrs.clone(),
            port: *port,
        })
        .collect();
    for (d, pd) in b.plan.devices.iter().enumerate() {
        if !matches!(pd.layout, Layout::Dedicated { .. }) || dedicated_forced() {
            continue;
        }
        let rec = b
            .res
            .record
            .as_mut()
            .ok_or_else(|| internal(&b.plan.interface, "no ownership record"))?;
        let rules = installer::install(
            b.nic,
            rec,
            &[(pd.name.clone(), pd.ifindex)],
            std::slice::from_ref(&pd.layout),
            &eps,
        )?;
        b.res.devices[d].rules = rules;
        j.record(Change::Rules { device: d });
    }
    let all: Vec<InstalledRule> = b
        .res
        .devices
        .iter()
        .flat_map(|d| d.rules.iter().cloned())
        .collect();
    installer::queues_unbound(b.nic, &all)?;
    installer::verify(b.nic, &all)?;
    Ok(())
}

fn attach(b: &mut Build<'_>, j: &mut Journal<Change>) -> Result<(), XdpError> {
    let interface = b.plan.interface.as_str();
    let drv = b.plan.mode == XdpMode::Drv;
    let mode = mode_name(b.plan.mode);
    let lock = b
        .lock
        .ok_or_else(|| internal(interface, "setup without the bpffs lock"))?;
    let order = {
        let names: Vec<&str> = b.res.devices.iter().map(|d| d.dev.name()).collect();
        b.res.pace.order(&names)
    };
    for d in order {
        let Resources {
            devices, pace: pc, ..
        } = &mut *b.res;
        let dr = &mut devices[d];
        let name = dr.dev.name().to_string();
        let device = dev_opt(interface, &name);
        pc.before(&name, "attach");
        let attach_mode = if drv {
            dispatcher::AttachMode::Native
        } else {
            dispatcher::AttachMode::Generic
        };
        let attached = dispatcher::attach_or_join(&dr.dev, attach_mode, lock);
        pc.after(&name);
        let dispatcher = attached.map_err(|e| {
            setup_err(
                interface,
                device,
                None,
                format!("cannot attach the classifier in {mode} mode: {e}"),
                if drv {
                    "the driver may not support native XDP: use skb mode, or follow the hint in the reason"
                } else {
                    "follow the hint in the reason; `ip link show dev <dev>` shows what holds the XDP hook"
                },
            )
        })?;
        dr.dispatcher = Some(dispatcher);
        j.record(Change::Member { device: d });
        let ebpf = dr
            .dispatcher
            .as_mut()
            .ok_or_else(|| internal(interface, "dispatcher vanished"))?
            .our_member_mut()
            .map_err(|e| internal(interface, &e.to_string()))?;
        dr.classifier = Some(Classifier::from_member(&name, ebpf)?);
    }
    Ok(())
}

fn open_sockets(b: &mut Build<'_>, j: &mut Journal<Change>) -> Result<(), XdpError> {
    for (d, pd) in b.plan.devices.iter().enumerate() {
        for (slot, queue) in pd.sockets(&b.plan.endpoints) {
            let dr = &mut b.res.devices[d];
            let bound = bind_queue(b.plan, &dr.dev, slot, queue)?;
            let fd = bound.socket.as_fd().as_raw_fd();
            dr.queues.push(Some(bound));
            j.record(Change::Socket {
                device: d,
                index: dr.queues.len() - 1,
                slot,
                queue,
            });
            dr.classifier
                .as_mut()
                .ok_or_else(|| internal(&b.plan.interface, "classifier missing"))?
                .register_xsk(slot, queue, fd)?;
        }
    }
    Ok(())
}

fn bind_queue(
    plan: &Plan,
    dev: &NetworkDevice,
    slot: u32,
    queue: u32,
) -> Result<BoundQueue, XdpError> {
    let err = |reason: String, remedy: &str| {
        setup_err(
            &plan.interface,
            dev_opt(&plan.interface, dev.name()),
            None,
            reason,
            remedy,
        )
    };
    let copy = if plan.zero_copy { "zero-copy" } else { "copy" };
    let mut mem =
        PageAlignedMemory::alloc(FRAME_SIZE as usize, FRAMES_PER_SOCKET).map_err(|e| {
            err(
                format!(
                    "cannot map {POOL_BYTES} bytes of frame memory for queue {queue}: {}",
                    e.0
                ),
                "free memory, or use a device with fewer receive queues",
            )
        })?;
    crate::quic::rings::place_frame_memory(&mem, dev.name()).map_err(|e| {
        err(
            format!("cannot lock {POOL_BYTES} bytes of frame memory for queue {queue} in memory: {e}"),
            "raise RLIMIT_MEMLOCK (`LimitMEMLOCK=infinity`, `ulimit -l unlimited`, `--ulimit memlock=-1`) or grant CAP_IPC_LOCK",
        )
    })?;
    let deadline = Instant::now() + installer::BUSY_RETRY;
    let (socket, rx, tx) = loop {
        let q = dev.open_queue(QueueId(u64::from(queue)));
        let umem = OwnedUmem::new(mem, FRAME_SIZE);
        match Socket::new_or_keep(q, umem, plan.zero_copy, RX_RING, RX_RING, TX_RING, TX_RING) {
            Ok(bound) => break bound,
            Err((e, umem)) if crate::nic::is_busy(&e) => {
                if Instant::now() >= deadline {
                    return Err(err(
                        format!(
                            "cannot bind an AF_XDP socket ({copy} mode) to queue {queue} of {}: queue {queue} is busy \
                             (possibly another AF_XDP socket), still after {:?}: {e}",
                            dev.name(),
                            installer::BUSY_RETRY
                        ),
                        "stop the other XDP user of the queue and restart",
                    ));
                }
                mem = umem.into_memory();
                std::thread::sleep(installer::BUSY_STEP);
            }
            Err((e, _)) => {
                return Err(err(
                    format!(
                        "cannot bind an AF_XDP socket ({copy} mode) to queue {queue} of {}: {e}",
                        dev.name()
                    ),
                    if plan.zero_copy {
                        "the driver may not support AF_XDP zero-copy on this device; turn zero-copy off"
                    } else {
                        "check that no other AF_XDP socket is bound to the queue and that the process has CAP_NET_RAW"
                    },
                ));
            }
        }
    };
    if plan.zero_copy {
        let on = zero_copy_active(&socket).map_err(|e| {
            err(
                format!("cannot read the AF_XDP options of queue {queue}: {e}"),
                "report this",
            )
        })?;
        if !on {
            return Err(err(
                format!(
                    "zero-copy was asked for but the kernel bound queue {queue} of {} in copy mode",
                    dev.name()
                ),
                "turn zero-copy off, or use a driver with AF_XDP zero-copy support",
            ));
        }
    }
    Ok(BoundQueue {
        queue,
        slot,
        socket,
        rx,
        tx,
    })
}

fn zero_copy_active(socket: &impl AsFd) -> io::Result<bool> {
    let mut opts = libc::xdp_options { flags: 0 };
    let mut len = size_of::<libc::xdp_options>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            libc::SOL_XDP,
            libc::XDP_OPTIONS,
            (&raw mut opts).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(opts.flags & libc::XDP_OPTIONS_ZEROCOPY != 0)
}

#[allow(clippy::result_large_err)]
pub(crate) fn undo(b: &mut Build<'_>, c: &Change) -> Result<(), Problem> {
    let Resources {
        reserved,
        record,
        devices,
        pace: pc,
        ..
    } = &mut *b.res;
    let no_device = || Problem::global("internal error: unknown device index");
    match *c {
        Change::Reserved { endpoint } => {
            if let Some(s) = reserved.get_mut(endpoint) {
                *s = None;
            }
            Ok(())
        }
        Change::Record => {
            let Some(owner) = record.take() else {
                return Ok(());
            };
            let dir = owner.dir().display().to_string();
            let left = owner.all().map_err(|e| {
                Problem::global_err("cannot read the ownership record", e)
                    .at(dir.as_str())
                    .leaving("ownership record")
            })?;
            if !left.is_empty() {
                return Err(Problem {
                    rule_count: Some(left.len()),
                    ..Problem::global("steering rules left in the ownership record")
                        .at(dir.as_str())
                        .leaving("ownership record")
                });
            }
            owner.remove().map_err(|e| {
                Problem::global_err("cannot remove the ownership record", e)
                    .at(dir.as_str())
                    .leaving("ownership record")
            })
        }
        Change::Rules { device } => {
            let dr = devices.get_mut(device).ok_or_else(no_device)?;
            let rules = std::mem::take(&mut dr.rules);
            let rec = record.as_mut().ok_or_else(|| {
                Problem::global("internal error: the ownership record went before its rules")
            })?;
            installer::uninstall(b.nic, rec, &rules).map_err(|e| {
                Problem::new(dr.dev.name(), "cannot delete steering rules", e).needs_attention()
            })
        }
        Change::Member { device } => {
            let dr = devices.get_mut(device).ok_or_else(no_device)?;
            dr.classifier = None;
            match dr.dispatcher.take() {
                Some(d) => match b.lock {
                    Some(lock) => {
                        let name = dr.dev.name().to_string();
                        pc.before(&name, "detach");
                        let left = d.leave(&dr.dev, lock).map_err(|e| {
                            Problem::new(dr.dev.name(), "cannot leave the XDP chain", e)
                                .leaving("chain member")
                        });
                        pc.after(&name);
                        left
                    }
                    None => {
                        d.abandon();
                        Ok(())
                    }
                },
                None => Ok(()),
            }
        }
        Change::Socket {
            device,
            index,
            slot,
            queue,
        } => {
            let dr = devices.get_mut(device).ok_or_else(no_device)?;
            let unregistered = match dr.classifier.as_mut() {
                Some(cl) => cl.unregister_xsk(slot, queue).map_err(|e| {
                    Problem::new(
                        dr.dev.name(),
                        "cannot remove a socket from the classifier",
                        e,
                    )
                }),
                None => Ok(()),
            };
            if let Some(q) = dr.queues.get_mut(index) {
                *q = None;
            }
            unregistered
        }
        Change::Owned { device, ip, port } => {
            let dr = devices.get_mut(device).ok_or_else(no_device)?;
            match dr.classifier.as_mut() {
                Some(cl) => cl.disown(ip, port).map_err(|e| {
                    Problem::new(
                        dr.dev.name(),
                        "cannot remove an endpoint key from the classifier",
                        e,
                    )
                }),
                None => Ok(()),
            }
        }
    }
}

pub(crate) fn teardown(
    nic: &dyn NicOps,
    lock: Option<&BpffsLock>,
    plan: &Plan,
    res: &mut Resources,
    journal: &mut Journal<Change>,
) -> Vec<Problem> {
    let mut b = Build {
        nic,
        lock,
        plan,
        res,
    };
    let mut errors = journal.unwind(&mut b, undo);
    let pending = std::mem::take(&mut res.deferred);
    errors.extend(finish_pending(pending, lock.map(Held::Flock)));
    errors
}

pub(crate) const LOCK_UNAVAILABLE: &str = "bpffs lock unavailable";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Problem {
    pub device: Option<String>,
    pub reason: &'static str,
    pub error: Option<String>,
    pub path: Option<String>,
    pub location: Option<u32>,
    pub rule_count: Option<usize>,
    pub leftover: Option<&'static str>,
    pub attention: bool,
}

impl Problem {
    pub(crate) fn new(
        device: impl Into<String>,
        reason: &'static str,
        error: impl ToString,
    ) -> Self {
        Self {
            error: Some(error.to_string()),
            ..Self::bare(device, reason)
        }
    }

    pub(crate) fn bare(device: impl Into<String>, reason: &'static str) -> Self {
        Self {
            device: Some(device.into()),
            ..Self::global(reason)
        }
    }

    pub(crate) const fn global(reason: &'static str) -> Self {
        Self {
            device: None,
            reason,
            error: None,
            path: None,
            location: None,
            rule_count: None,
            leftover: None,
            attention: false,
        }
    }

    pub(crate) fn global_err(reason: &'static str, error: impl ToString) -> Self {
        Self {
            error: Some(error.to_string()),
            ..Self::global(reason)
        }
    }

    pub(crate) fn at(self, path: &str) -> Self {
        Self {
            path: Some(path.to_string()),
            ..self
        }
    }

    pub(crate) fn leaving(self, leftover: &'static str) -> Self {
        Self {
            leftover: Some(leftover),
            ..self
        }
    }

    pub(crate) fn needs_attention(self) -> Self {
        Self {
            attention: true,
            ..self
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(d) = &self.device {
            write!(f, "{d}: ")?;
        }
        f.write_str(self.reason)?;
        if let Some(p) = &self.path {
            write!(f, " ({p})")?;
        }
        if let Some(l) = self.location {
            write!(f, " (rule location {l})")?;
        }
        if let Some(n) = self.rule_count {
            write!(f, " ({n} rules)")?;
        }
        if let Some(e) = &self.error {
            write!(f, ": {e}")?;
        }
        if let Some(l) = self.leftover {
            write!(f, "; {l} kept for the next start")?;
        }
        Ok(())
    }
}

pub(crate) fn finish_pending(pending: Vec<PendingLeave>, lock: Option<Held<'_>>) -> Vec<Problem> {
    match lock {
        Some(l) => leave_pending(pending, l).1,
        None => {
            for p in pending {
                p.abandon();
            }
            Vec::new()
        }
    }
}

pub(crate) fn disarm(
    plan: &Plan,
    res: &mut Resources,
    journal: &mut Journal<Change>,
    endpoint: usize,
) -> Option<Vec<Problem>> {
    let ep = plan.endpoints.get(endpoint)?;
    let armed = res.armed.get(endpoint).copied().unwrap_or(false);
    let dedicated = plan.kind == LayoutKind::Dedicated;
    if !armed && !dedicated {
        return None;
    }
    let Some(port) = res.ports.get(endpoint).copied() else {
        return Some(vec![Problem::global(
            "internal error: no port for the endpoint",
        )]);
    };
    let mut errors = Vec::new();
    for (d, dr) in res
        .devices
        .iter_mut()
        .enumerate()
        .filter(|(_, dr)| !dr.retired)
    {
        let Some(cl) = dr.classifier.as_mut() else {
            errors.push(Problem::bare(
                dr.dev.name(),
                "internal error: classifier missing",
            ));
            continue;
        };
        for ip in ep.addrs.iter().filter(|_| armed) {
            match cl.disown(*ip, port) {
                Ok(()) => journal.retain(|c| {
                    *c != Change::Owned {
                        device: d,
                        ip: *ip,
                        port,
                    }
                }),
                Err(e) => {
                    dr.drops_off = true;
                    errors.push(Problem::new(
                        dr.dev.name(),
                        "cannot remove an endpoint key from the classifier",
                        e,
                    ));
                }
            }
        }
        if !dedicated {
            continue;
        }
        for (slot, queue) in cl.registered().into_iter().filter(|(s, _)| *s == ep.slot) {
            match cl.unregister_xsk(slot, queue) {
                Ok(()) => journal.retain(|c| {
                    !matches!(*c, Change::Socket { device, slot: s, queue: q, .. } if device == d && s == slot && q == queue)
                }),
                Err(e) => {
                    cl.forget_xsk(slot, queue);
                    errors.push(Problem::new(dr.dev.name(), "cannot remove a socket from the classifier", e));
                }
            }
        }
    }
    Some(errors)
}

pub(crate) fn forget_sockets(
    res: &mut Resources,
    journal: &mut Journal<Change>,
    devices: &[usize],
    slot: u32,
) -> Vec<String> {
    let mut errors = Vec::new();
    for &d in devices {
        let Some(dr) = res.devices.get_mut(d) else {
            continue;
        };
        if let Some(cl) = dr.classifier.as_mut() {
            for (s, queue) in cl.registered().into_iter().filter(|(s, _)| *s == slot) {
                if let Err(e) = cl.unregister_xsk(s, queue) {
                    cl.forget_xsk(s, queue);
                    errors.push(e.to_string());
                }
            }
        }
        journal.retain(
            |c| !matches!(*c, Change::Socket { device, slot: s, .. } if device == d && s == slot),
        );
    }
    errors
}

pub(crate) fn arm(
    plan: &Plan,
    res: &mut Resources,
    journal: &mut Journal<Change>,
    endpoint: usize,
) -> Result<(), XdpError> {
    let interface = plan.interface.as_str();
    let ep = plan
        .endpoints
        .get(endpoint)
        .ok_or_else(|| internal(interface, "no such endpoint"))?;
    if res.armed.get(endpoint).copied().unwrap_or(true) {
        return Err(setup_err(
            interface,
            None,
            Some(ep.name),
            "the endpoint is already in use",
            "take each endpoint once",
        ));
    }
    let port = res.ports[endpoint];
    let mut done = Vec::new();
    let mut failure = None;
    'devices: for (d, dr) in res
        .devices
        .iter_mut()
        .enumerate()
        .filter(|(_, dr)| !dr.retired)
    {
        let Some(cl) = dr.classifier.as_mut() else {
            failure = Some(internal(interface, "classifier missing"));
            break;
        };
        for ip in &ep.addrs {
            if let Err(e) = cl.own(*ip, port, ep.slot, Miss::Drop) {
                failure = Some(e);
                break 'devices;
            }
            done.push(Change::Owned {
                device: d,
                ip: *ip,
                port,
            });
        }
    }
    if let Some(e) = failure {
        let mut errors = Vec::new();
        for c in done.iter().rev() {
            if let Change::Owned { device, ip, port } = *c
                && let Some(cl) = res
                    .devices
                    .get_mut(device)
                    .and_then(|d| d.classifier.as_mut())
                && let Err(ue) = cl.disown(ip, port)
            {
                errors.push(ue.to_string());
            }
        }
        return Err(with_rollback_errors(e, interface, &errors));
    }
    for c in done {
        journal.record(c);
    }
    res.armed[endpoint] = true;
    Ok(())
}

pub(crate) enum PendingLeave {
    Member {
        dev: NetworkDevice,
        dispatcher: Dispatcher,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum Held<'a> {
    Flock(&'a BpffsLock),
}

impl PendingLeave {
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Member { dev, .. } => dev.name().to_string(),
        }
    }

    pub(crate) fn abandon(self) {
        match self {
            Self::Member { dispatcher, .. } => dispatcher.abandon(),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn leave(self, lock: Held<'_>) -> Result<(), Problem> {
        match (self, lock) {
            (Self::Member { dev, dispatcher }, Held::Flock(l)) => dispatcher
                .leave(&dev, l)
                .map_err(|e| Problem::new(dev.name(), "cannot leave the XDP chain", e)),
        }
    }
}

pub(crate) fn leave_pending(
    pending: Vec<PendingLeave>,
    lock: Held<'_>,
) -> (Vec<String>, Vec<Problem>) {
    let mut left = Vec::new();
    let mut errors = Vec::new();
    for p in pending {
        let name = p.name();
        match p.leave(lock) {
            Ok(()) => left.push(name),
            Err(e) => errors.push(e),
        }
    }
    (left, errors)
}

pub(crate) enum TryLock<'a> {
    Held(Held<'a>),
    Busy,
    Failed(String),
}

fn leave_or_defer(
    p: PendingLeave,
    lock: TryLock<'_>,
    errors: &mut Vec<Problem>,
) -> Option<PendingLeave> {
    match lock {
        TryLock::Held(l) => {
            if let Err(e) = p.leave(l) {
                errors.push(e);
            }
            None
        }
        TryLock::Busy => Some(p),
        TryLock::Failed(e) => {
            errors.push(Problem::new(p.name(), LOCK_UNAVAILABLE, e));
            Some(p)
        }
    }
}

pub(crate) struct Retiring {
    pub device: usize,
    pub dev: NetworkDevice,
    member: Option<PendingLeave>,
    classifier: Option<Classifier>,
    rules: Vec<InstalledRule>,
    pub unhanded: Vec<BoundQueue>,
    owned: Vec<(Ipv4Addr, u16)>,
}

pub(crate) fn take_device(
    res: &mut Resources,
    journal: &mut Journal<Change>,
    device: usize,
) -> Option<Retiring> {
    let dr = res.devices.get_mut(device)?;
    if dr.retired {
        return None;
    }
    dr.retired = true;
    let mut owned = Vec::new();
    journal.retain(|c| match *c {
        Change::Owned {
            device: d,
            ip,
            port,
        } if d == device => {
            owned.push((ip, port));
            false
        }
        Change::Rules { device: d }
        | Change::Member { device: d }
        | Change::Socket { device: d, .. } => d != device,
        _ => true,
    });
    Some(Retiring {
        device,
        dev: dr.dev.clone(),
        member: dr.dispatcher.take().map(|dispatcher| PendingLeave::Member {
            dev: dr.dev.clone(),
            dispatcher,
        }),
        classifier: dr.classifier.take(),
        rules: std::mem::take(&mut dr.rules),
        unhanded: dr.queues.iter_mut().filter_map(Option::take).collect(),
        owned,
    })
}

pub(crate) struct Released {
    pub device: usize,
    pub forget: Vec<InstalledRule>,
    pub kept: Vec<InstalledRule>,
    pub errors: Vec<Problem>,
    pub pending: Option<PendingLeave>,
}

#[derive(Default)]
struct Deferred(Vec<InstalledRule>);

impl RecordStore for Deferred {
    fn put(&mut self, _: &InstalledRule) -> io::Result<()> {
        Err(io::Error::other(
            "internal error: a retirement records no rule",
        ))
    }

    fn remove(&mut self, r: &InstalledRule) -> io::Result<()> {
        self.0.push(r.clone());
        Ok(())
    }

    fn all(&self) -> io::Result<Vec<InstalledRule>> {
        Ok(self.0.clone())
    }
}

pub(crate) fn disown_retiring(t: &mut Retiring) -> Vec<Problem> {
    let mut errors = Vec::new();
    let owned = std::mem::take(&mut t.owned);
    let name = t.dev.name().to_string();
    if let Some(cl) = t.classifier.as_mut() {
        for (ip, port) in owned {
            if let Err(e) = cl.disown(ip, port) {
                errors.push(Problem::new(
                    name.as_str(),
                    "cannot remove an endpoint key from the classifier",
                    e,
                ));
            }
        }
        for (slot, queue) in cl.registered() {
            if let Err(e) = cl.unregister_xsk(slot, queue) {
                cl.forget_xsk(slot, queue);
                errors.push(Problem::new(
                    name.as_str(),
                    "cannot remove a socket from the classifier",
                    e,
                ));
            }
        }
    }
    errors
}

#[allow(clippy::type_complexity)]
pub(crate) fn release(
    nic: &dyn NicOps,
    t: Retiring,
    try_lock: &mut dyn FnMut(&mut dyn FnMut(TryLock<'_>)),
) -> Released {
    let Retiring {
        device,
        dev,
        member,
        classifier,
        rules,
        unhanded,
        owned: _,
    } = t;
    let name = dev.name().to_string();
    let mut errors = Vec::new();
    drop(unhanded);
    drop(classifier);
    let mut pending = None;
    if let Some(p) = member {
        let mut p = Some(p);
        try_lock(&mut |lock| {
            if let Some(m) = p.take() {
                pending = leave_or_defer(m, lock, &mut errors);
            }
        });
        if let Some(m) = p {
            pending = Some(m);
        }
    }
    let mut forget = Vec::new();
    let mut kept = Vec::new();
    for r in rules {
        let mut d = Deferred::default();
        match installer::uninstall(nic, &mut d, std::slice::from_ref(&r)) {
            Ok(()) => forget.extend(d.0),
            Err(e) => match interface_gone(r.ifindex) {
                Ok(true) => forget.push(r),
                Ok(false) => {
                    errors.push(Problem::new(
                        name.as_str(),
                        "cannot delete a steering rule",
                        e,
                    ));
                    kept.push(r);
                }
                Err(ge) => {
                    errors.push(Problem::new(
                        name.as_str(),
                        "cannot delete a steering rule",
                        e,
                    ));
                    errors.push(Problem::new(
                        name.as_str(),
                        "cannot tell whether the device still exists",
                        ge,
                    ));
                    kept.push(r);
                }
            },
        }
    }
    Released {
        device,
        forget,
        kept,
        errors,
        pending,
    }
}

pub(crate) fn settle(
    res: &mut Resources,
    journal: &mut Journal<Change>,
    r: Released,
) -> Vec<Problem> {
    let mut errors = r.errors;
    if let Some(p) = r.pending {
        res.deferred.push(p);
    }
    match res.record.as_mut() {
        Some(rec) => {
            for rule in &r.forget {
                if let Err(e) = RecordStore::remove(rec, rule) {
                    errors.push(Problem {
                        location: Some(rule.location),
                        ..Problem::new(
                            rule.device.as_str(),
                            "cannot drop a deleted rule's record entry",
                            e,
                        )
                    });
                }
            }
        }
        None if !r.forget.is_empty() => {
            let name = res
                .devices
                .get(r.device)
                .map_or_else(String::new, |d| d.dev.name().to_string());
            errors.push(Problem::bare(
                name,
                "internal error: no ownership record for the retired rules",
            ));
        }
        None => {}
    }
    if !r.kept.is_empty()
        && let Some(dr) = res.devices.get_mut(r.device)
    {
        dr.rules.extend(r.kept);
        journal.record(Change::Rules { device: r.device });
    }
    errors
}
