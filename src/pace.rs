
use {
    crate::slaves::{Ineligible, SysfsRoot, eligibility},
    std::time::{Duration, Instant},
};

pub(crate) const RECOVERY_BOUND: Duration = Duration::from_secs(15);
pub(crate) const SETTLE: Duration = Duration::from_millis(150);
pub(crate) const BLIND_HOLD: Duration = Duration::from_secs(5);
const TIMERS_FALLBACK: Duration = Duration::from_secs(1);
pub(crate) const POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lacp {
    Ready,
    NotReady,
    Unreadable,
}

pub(crate) trait PaceEnv: Send {
    fn bond_of(&self, slave: &str) -> Option<String>;
    fn slaves(&self, bond: &str) -> Option<Vec<String>>;
    fn lacp(&self, bond: &str, slave: &str) -> Lacp;
    fn carrier(&self, slave: &str) -> bool;
    fn carrier_changes(&self, slave: &str) -> Option<u64>;
    fn link_timers(&self, bond: &str) -> Option<Duration>;
    fn now(&self) -> Duration;
    fn sleep(&self, d: Duration);
}

struct SystemEnv {
    root: SysfsRoot,
    origin: Instant,
}

impl PaceEnv for SystemEnv {
    fn bond_of(&self, slave: &str) -> Option<String> {
        self.root.bond_of(slave)
    }

    fn slaves(&self, bond: &str) -> Option<Vec<String>> {
        self.root.slave_names(bond)
    }

    fn lacp(&self, bond: &str, slave: &str) -> Lacp {
        let (_, verdicts) = eligibility(&self.root, bond, &[slave]);
        match verdicts.into_iter().next() {
            Some(Ok(())) => Lacp::Ready,
            Some(Err(
                Ineligible::Unreadable(_) | Ineligible::NotRead | Ineligible::BadPortState { .. },
            ))
            | None => Lacp::Unreadable,
            Some(Err(_)) => Lacp::NotReady,
        }
    }

    fn carrier(&self, slave: &str) -> bool {
        self.root.carrier_up(slave)
    }

    fn carrier_changes(&self, slave: &str) -> Option<u64> {
        self.root.carrier_changes(slave)
    }

    fn link_timers(&self, bond: &str) -> Option<Duration> {
        self.root.link_timers(bond)
    }

    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

pub(crate) enum Scope {
    Off,
    Bond(String, Vec<String>),
    Auto,
}

struct Last {
    slave: String,
    changes: Option<u64>,
    at: Duration,
}

struct Touch {
    slave: String,
    changes: Option<u64>,
}

pub(crate) struct Pace {
    scope: Scope,
    env: Box<dyn PaceEnv>,
    bound: Duration,
    touching: Option<Touch>,
    last: Option<Last>,
    blind_warned: bool,
}

pub(crate) const fn needed(bond: bool, drv: bool, devices: usize) -> bool {
    bond && drv && devices > 1
}

#[derive(Default)]
struct Sibling {
    seen_down: bool,
    up_since: Option<Duration>,
}

impl Pace {
    pub(crate) fn with_env(scope: Scope, env: Box<dyn PaceEnv>, bound: Duration) -> Self {
        Self {
            scope,
            env,
            bound,
            touching: None,
            last: None,
            blind_warned: false,
        }
    }

    fn system(scope: Scope) -> Self {
        let env = SystemEnv {
            root: SysfsRoot::system(),
            origin: Instant::now(),
        };
        Self::with_env(scope, Box::new(env), RECOVERY_BOUND)
    }

    pub(crate) fn off() -> Self {
        Self::system(Scope::Off)
    }

    pub(crate) fn for_bond(bond: &str, slaves: Vec<String>, active: bool) -> Self {
        if active {
            Self::system(Scope::Bond(bond.to_string(), slaves))
        } else {
            Self::off()
        }
    }

    pub(crate) fn auto() -> Self {
        Self::system(Scope::Auto)
    }

    fn peers(&self, slave: &str) -> Option<(String, Vec<String>)> {
        let (bond, known) = match &self.scope {
            Scope::Off => return None,
            Scope::Bond(b, names) => (b.clone(), Some(names)),
            Scope::Auto => (self.env.bond_of(slave)?, None),
        };
        let all = self
            .env
            .slaves(&bond)
            .or_else(|| known.cloned())
            .unwrap_or_default();
        let others: Vec<String> = all.into_iter().filter(|n| n != slave).collect();
        (!others.is_empty()).then_some((bond, others))
    }

    pub(crate) fn order(&self, names: &[&str]) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..names.len()).collect();
        let Scope::Bond(bond, _) = &self.scope else {
            return idx;
        };
        let ready: Vec<bool> = names
            .iter()
            .map(|n| self.env.lacp(bond, n) == Lacp::Ready)
            .collect();
        idx.sort_by_key(|&i| ready[i]);
        idx
    }

    pub(crate) fn before(&mut self, slave: &str, operation: &'static str) -> bool {
        self.touching = None;
        let Some((bond, others)) = self.peers(slave) else {
            return false;
        };
        let expired = !self.wait_for_peer(&bond, slave, &others, operation);
        let changes = self.env.carrier_changes(slave);
        self.touching = Some(Touch {
            slave: slave.to_string(),
            changes,
        });
        expired
    }

    pub(crate) fn after(&mut self, slave: &str) {
        let Some(t) = self.touching.take() else {
            return;
        };
        if t.slave == slave {
            self.last = Some(Last {
                slave: t.slave,
                changes: t.changes,
                at: self.env.now(),
            });
        }
    }

    fn wait_for_peer(
        &mut self,
        bond: &str,
        slave: &str,
        others: &[String],
        operation: &'static str,
    ) -> bool {
        let start = self.env.now();
        let timers = self.env.link_timers(bond).unwrap_or(TIMERS_FALLBACK);
        let mut state: Vec<Sibling> = others.iter().map(|_| Sibling::default()).collect();
        let mut waited_for: Option<&str> = None;
        loop {
            let now = self.env.now();
            let mut usable: Option<usize> = None;
            for (i, name) in others.iter().enumerate() {
                let lacp = self.env.lacp(bond, name);
                let st = &mut state[i];
                let (restarted, settle_from) = match &self.last {
                    Some(l) if l.slave == *name => (
                        l.changes.is_none() || self.env.carrier_changes(name) != l.changes,
                        Some(l.at),
                    ),
                    _ => (false, None),
                };
                let ok = match lacp {
                    Lacp::NotReady => {
                        st.seen_down = true;
                        st.up_since = None;
                        false
                    }
                    Lacp::Ready | Lacp::Unreadable => {
                        let blind = lacp == Lacp::Unreadable;
                        if blind && !self.blind_warned {
                            self.blind_warned = true;
                            log_blind(bond, name);
                        }
                        if blind && !self.env.carrier(name) {
                            st.seen_down = true;
                            st.up_since = None;
                            false
                        } else {
                            let since = *st.up_since.get_or_insert(now);
                            let held = now.saturating_sub(since);
                            if st.seen_down || restarted {
                                held >= if blind { BLIND_HOLD } else { timers + SETTLE }
                            } else {
                                settle_from.is_none_or(|at| now.saturating_sub(at) >= SETTLE)
                            }
                        }
                    }
                };
                if ok {
                    usable = Some(i);
                    break;
                }
                if st.seen_down || restarted {
                    waited_for = Some(name.as_str());
                }
            }
            if let Some(i) = usable {
                if now > start && (state[i].seen_down || waited_for.is_some()) {
                    tracing::info!(
                        bond = %bond,
                        device = %others[i],
                        operation,
                        state = "recovered",
                        waited_ms = now.saturating_sub(start).as_millis() as u64,
                        "XDP bond slave recovered"
                    );
                }
                return true;
            }
            if now.saturating_sub(start) >= self.bound {
                tracing::warn!(
                    bond = %bond,
                    device = %slave,
                    operation,
                    wait_ms = self.bound.as_millis() as u64,
                    state = "degraded",
                    reason = "no other slave eligible",
                    action = "continue",
                    risk = "the bond loses its links while the port restarts",
                    "XDP bond slave has no eligible peer"
                );
                return false;
            }
            self.env.sleep(POLL);
        }
    }
}

fn log_blind(bond: &str, device: &str) {
    tracing::warn!(
        bond = %bond,
        device = %device,
        state = "degraded",
        reason = "LACP state unreadable",
        wait_ms = BLIND_HOLD.as_millis() as u64,
        action = "wait for carrier",
        "XDP bond slave state unreadable"
    );
}
