use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) struct Eligibility {
    mask: AtomicU64,
}

impl Eligibility {
    pub(crate) const fn new(mask: u64) -> Self {
        Self {
            mask: AtomicU64::new(mask),
        }
    }

    pub(crate) fn publish(&self, mask: u64) {
        self.mask.store(mask, Ordering::Release);
    }

    pub(crate) fn mask(&self) -> u64 {
        self.mask.load(Ordering::Acquire)
    }
}

pub(crate) const fn pick_slave(mask: u64, learned: Option<u8>, peer_hash: u32) -> Option<u8> {
    if mask == 0 {
        return None;
    }
    if let Some(l) = learned
        && l < 64
        && mask & (1u64 << l) != 0
    {
        return Some(l);
    }
    let mut n = peer_hash % mask.count_ones();
    let mut m = mask;
    loop {
        let bit = m.trailing_zeros();
        if n == 0 {
            return Some(bit as u8);
        }
        m &= m - 1;
        n -= 1;
    }
}

const DISTRIBUTING: u32 = 0x20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ineligible {
    CarrierDown,
    NoActiveAggregator,
    NoAggregator,
    AggregatorMismatch { aggregator: String, active: String },
    NotDistributing { port_state: u32 },
    BadPortState { text: String },
    Unreadable(ReadError),
    NotRead,
}

impl Ineligible {
    pub(crate) const fn reason(&self) -> &'static str {
        match self {
            Self::CarrierDown => "carrier down",
            Self::NoActiveAggregator => "no active aggregator",
            Self::NoAggregator => "no aggregator",
            Self::AggregatorMismatch { .. } => "aggregator mismatch",
            Self::NotDistributing { .. } => "not distributing",
            Self::BadPortState { .. } => "unparsable port state",
            Self::Unreadable(_) => "unreadable",
            Self::NotRead => "not read",
        }
    }
}

pub(crate) fn verdict(
    carrier: &str,
    slave_agg: &str,
    port_state: &str,
    active_agg: &str,
) -> Result<(), Ineligible> {
    let (slave_agg, active_agg) = (slave_agg.trim(), active_agg.trim());
    if carrier.trim() != "1" {
        return Err(Ineligible::CarrierDown);
    }
    if active_agg.is_empty() {
        return Err(Ineligible::NoActiveAggregator);
    }
    if slave_agg.is_empty() {
        return Err(Ineligible::NoAggregator);
    }
    if slave_agg != active_agg {
        return Err(Ineligible::AggregatorMismatch {
            aggregator: slave_agg.to_string(),
            active: active_agg.to_string(),
        });
    }
    match port_state.trim().parse::<u32>() {
        Ok(s) if s & DISTRIBUTING != 0 => Ok(()),
        Ok(s) => Err(Ineligible::NotDistributing { port_state: s }),
        Err(_) => Err(Ineligible::BadPortState {
            text: port_state.trim().to_string(),
        }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadError {
    pub path: String,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SlaveState {
    pub carrier: String,
    pub aggregator: String,
    pub port_state: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SysfsRoot(PathBuf);

impl SysfsRoot {
    pub(crate) fn system() -> Self {
        Self(PathBuf::from("/sys/class/net"))
    }

    fn read(&self, dev: &str, file: &str) -> Result<String, (io::Error, String)> {
        let path = self.0.join(dev).join(file);
        fs::read_to_string(&path).map_err(|e| (e, path.display().to_string()))
    }

    fn read_text(&self, dev: &str, file: &str) -> Result<String, ReadError> {
        self.read(dev, file).map_err(|(e, path)| ReadError {
            path,
            error: e.to_string(),
        })
    }

    pub(crate) fn bond_of(&self, slave: &str) -> Option<String> {
        let dir = self.0.join(slave);
        if !dir.join("bonding_slave").exists() {
            return None;
        }
        let master = fs::read_link(dir.join("master")).ok()?;
        Some(master.file_name()?.to_string_lossy().into_owned())
    }

    pub(crate) fn slave_names(&self, bond: &str) -> Option<Vec<String>> {
        let t = self.read(bond, "bonding/slaves").ok()?;
        Some(t.split_whitespace().map(str::to_string).collect())
    }

    pub(crate) fn carrier_up(&self, slave: &str) -> bool {
        carrier(self.read(slave, "carrier")).is_ok_and(|c| c.trim() == "1")
    }

    pub(crate) fn carrier_changes(&self, slave: &str) -> Option<u64> {
        self.read(slave, "carrier_changes")
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    pub(crate) fn link_timers(&self, bond: &str) -> Option<std::time::Duration> {
        let ms = |f: &str| -> Option<u64> {
            self.read(bond, &format!("bonding/{f}"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let sum = ms("miimon")? + ms("downdelay").unwrap_or(0) + ms("updelay").unwrap_or(0);
        Some(std::time::Duration::from_millis(sum))
    }

    pub(crate) fn members(&self, bond: &str) -> Result<Vec<(String, u32)>, ReadError> {
        let names = self.read_text(bond, "bonding/slaves")?;
        let mut out = Vec::new();
        for name in names.split_whitespace() {
            match self.read(name, "ifindex") {
                Ok(t) => {
                    let i = t.trim().parse::<u32>().map_err(|e| ReadError {
                        path: self.0.join(name).join("ifindex").display().to_string(),
                        error: format!("not an interface index '{}': {e}", t.trim()),
                    })?;
                    out.push((name.to_string(), i));
                }
                Err((e, _)) if vanishing(&e) => {}
                Err((e, path)) => {
                    return Err(ReadError {
                        path,
                        error: e.to_string(),
                    });
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn active_aggregator(&self, bond: &str) -> Result<String, ReadError> {
        self.read_text(bond, "bonding/ad_aggregator")
    }

    pub(crate) fn slave_state(&self, slave: &str) -> Result<SlaveState, ReadError> {
        Ok(SlaveState {
            carrier: carrier(self.read(slave, "carrier"))?,
            aggregator: self.read_text(slave, "bonding_slave/ad_aggregator_id")?,
            port_state: self.read_text(slave, "bonding_slave/ad_actor_oper_port_state")?,
        })
    }
}

fn vanishing(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENODEV))
}

fn carrier(r: Result<String, (io::Error, String)>) -> Result<String, ReadError> {
    match r {
        Ok(t) => Ok(t),
        Err((e, _)) if e.raw_os_error() == Some(libc::EINVAL) => Ok("0".into()),
        Err((e, path)) => Err(ReadError {
            path,
            error: e.to_string(),
        }),
    }
}

pub(crate) fn eligibility(
    root: &SysfsRoot,
    bond: &str,
    slaves: &[&str],
) -> (u64, Vec<Result<(), Ineligible>>) {
    let active = root.active_aggregator(bond);
    let mut mask = 0u64;
    let mut out = Vec::with_capacity(slaves.len());
    for (i, s) in slaves.iter().enumerate() {
        let v = judge(active.as_ref(), root.slave_state(s));
        if v.is_ok() && i < 64 {
            mask |= 1 << i;
        }
        out.push(v);
    }
    (mask, out)
}

pub(crate) fn judge(
    active: Result<&String, &ReadError>,
    state: Result<SlaveState, ReadError>,
) -> Result<(), Ineligible> {
    let active = active.map_err(|e| Ineligible::Unreadable(e.clone()))?;
    let st = state.map_err(Ineligible::Unreadable)?;
    verdict(&st.carrier, &st.aggregator, &st.port_state, active)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MembershipEvent {
    Retired { name: String, ifindex: u32 },
    Added { name: String, ifindex: u32 },
}

pub(crate) fn membership_diff(
    managed: &[(String, u32)],
    current: &[(String, u32)],
) -> Vec<MembershipEvent> {
    let mut out: Vec<MembershipEvent> = managed
        .iter()
        .filter(|m| !current.contains(m))
        .map(|(name, ifindex)| MembershipEvent::Retired {
            name: name.clone(),
            ifindex: *ifindex,
        })
        .collect();
    out.extend(
        current
            .iter()
            .filter(|c| !managed.contains(c))
            .map(|(name, ifindex)| MembershipEvent::Added {
                name: name.clone(),
                ifindex: *ifindex,
            }),
    );
    out
}
