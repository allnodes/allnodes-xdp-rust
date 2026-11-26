
use {
    crate::{
        error::XdpError,
        nic::{InstalledRule, NicOps, NicRule, RuleSpec, RxChannels},
    },
    std::{cmp::Reverse, collections::BTreeSet, io, net::Ipv4Addr, time::Duration},
};

pub(crate) trait RecordStore {
    fn put(&mut self, r: &InstalledRule) -> io::Result<()>;
    fn remove(&mut self, r: &InstalledRule) -> io::Result<()>;
    fn all(&self) -> io::Result<Vec<InstalledRule>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointPlan {
    pub name: &'static str,
    pub slot: u32,
    pub addrs: Vec<Ipv4Addr>,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    Dedicated { queues: Vec<u32> },
    Shared { queues: u32 },
}

fn setup_err(dev: &str, endpoint: Option<String>, reason: String, remedy: &str) -> XdpError {
    XdpError::Setup {
        interface: dev.to_string(),
        device: None,
        endpoint,
        reason,
        remedy: remedy.to_string(),
    }
}

fn io_err(dev: &str, what: &str, e: &io::Error) -> XdpError {
    setup_err(
        dev,
        None,
        format!("{what}: {e}"),
        "check that the interface exists and the process has CAP_NET_ADMIN; nothing was changed",
    )
}

pub(crate) fn plan(nic: &dyn NicOps, dev: &str, endpoints: usize) -> Result<Layout, XdpError> {
    let channels = nic
        .rx_channels(dev)
        .map_err(|e| io_err(dev, "cannot read the channel count", &e))?;
    let queues = channels.total();
    let ntuple = nic
        .supports_ntuple(dev)
        .map_err(|e| io_err(dev, "cannot read the ntuple feature", &e))?;
    if !ntuple {
        if queues == 0 {
            return Err(setup_err(
                dev,
                None,
                "the device has no receive queues".into(),
                "use a device that exposes at least one receive queue",
            ));
        }
        return Ok(Layout::Shared { queues });
    }
    let rules = nic
        .rules(dev)
        .map_err(|e| io_err(dev, "cannot read the steering rules", &e))?;
    let rss = nic
        .rss_queues(dev)
        .map_err(|e| io_err(dev, "cannot read the RSS indirection table", &e))?;
    let busy: BTreeSet<u32> = rules.iter().flat_map(NicRule::queues).collect();
    let mut candidates: Vec<u32> = (0..queues).filter(|q| !busy.contains(q)).collect();
    candidates.sort_by_key(|q| (rss.contains(q), Reverse(*q)));

    let mut chosen = Vec::with_capacity(endpoints);
    for q in candidates {
        if chosen.len() == endpoints {
            break;
        }
        let bound = nic.queue_has_xsk(dev, q).map_err(|e| {
            io_err(
                dev,
                &format!("cannot probe queue {q} for AF_XDP sockets"),
                &e,
            )
        })?;
        if !bound {
            chosen.push(q);
        }
    }
    if chosen.len() < endpoints {
        let missing = u32::try_from(endpoints - chosen.len()).unwrap_or(u32::MAX);
        let RxChannels { combined, rx_only } = channels;
        let command = if rx_only == 0 {
            format!(
                "ethtool -L {dev} combined {}",
                combined.saturating_add(missing)
            )
        } else {
            format!("ethtool -L {dev} rx {}", rx_only.saturating_add(missing))
        };
        return Err(setup_err(
            dev,
            None,
            format!(
                "needs {endpoints} free receive queue(s) but only {} of {queues} are free \
                 ({combined} combined and {rx_only} rx-only channels; the others are used by \
                 steering rules, RSS contexts or AF_XDP sockets)",
                chosen.len()
            ),
            &format!(
                "run `{command}` yourself (this endpoint setup never changes channel counts), or free \
                 queues by stopping their other users"
            ),
        ));
    }
    Ok(Layout::Dedicated { queues: chosen })
}

fn label(r: &InstalledRule) -> String {
    format!("{}:{} (slot {})", r.spec.dst_ip, r.spec.dst_port, r.slot)
}

fn rule_err(r: &InstalledRule, what: &str, e: &io::Error) -> XdpError {
    setup_err(
        &r.device,
        Some(label(r)),
        format!("{what} at location {}: {e}", r.location),
        "the steering rule record is kept; restart the service to retry cleanup, or inspect with `ethtool -n`",
    )
}

fn remove_one(
    nic: &dyn NicOps,
    rec: &mut dyn RecordStore,
    r: &InstalledRule,
) -> Result<bool, XdpError> {
    let current = nic
        .rules(&r.device)
        .map_err(|e| rule_err(r, "cannot read the rules", &e))?;
    let mut deleted = false;
    let ours = current
        .iter()
        .any(|c| c.location == r.location && c.as_ours().as_ref() == Some(&r.spec));
    if ours {
        match nic.delete_rule(&r.device, r.location) {
            Ok(()) => deleted = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(rule_err(r, "cannot delete the rule", &e)),
        }
    }
    rec.remove(r)
        .map_err(|e| rule_err(r, "cannot update the record", &e))?;
    Ok(deleted)
}

pub(crate) fn install(
    nic: &dyn NicOps,
    rec: &mut dyn RecordStore,
    devices: &[(String, u32)],
    layouts: &[Layout],
    eps: &[EndpointPlan],
) -> Result<Vec<InstalledRule>, XdpError> {
    if devices.len() != layouts.len() {
        return Err(setup_err(
            devices.first().map_or("(no device)", |d| d.0.as_str()),
            None,
            format!("{} devices but {} layouts", devices.len(), layouts.len()),
            "internal error: report this",
        ));
    }
    let mut done: Vec<InstalledRule> = Vec::new();
    let result = install_all(nic, rec, devices, layouts, eps, &mut done);
    if let Err(e) = result {
        let mut failures = Vec::new();
        for r in done.iter().rev() {
            if let Err(re) = remove_one(nic, rec, r) {
                failures.push(re.to_string());
            }
        }
        return Err(if failures.is_empty() {
            e
        } else {
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
                    reason: format!("{reason}; rollback also failed: {}", failures.join("; ")),
                    remedy,
                },
                other => other,
            }
        });
    }
    Ok(done)
}

fn install_all(
    nic: &dyn NicOps,
    rec: &mut dyn RecordStore,
    devices: &[(String, u32)],
    layouts: &[Layout],
    eps: &[EndpointPlan],
    done: &mut Vec<InstalledRule>,
) -> Result<(), XdpError> {
    for ((dev, ifindex), layout) in devices.iter().zip(layouts) {
        let Layout::Dedicated { queues } = layout else {
            continue;
        };
        for ep in eps {
            let queue = usize::try_from(ep.slot)
                .ok()
                .and_then(|s| queues.get(s))
                .copied();
            let Some(queue) = queue else {
                return Err(setup_err(
                    dev,
                    Some(ep.name.to_string()),
                    format!("no queue planned for slot {}", ep.slot),
                    "internal error: report this",
                ));
            };
            for addr in &ep.addrs {
                let spec = RuleSpec {
                    dst_ip: *addr,
                    dst_port: ep.port,
                    queue,
                };
                let tag = format!("{addr}:{} (slot {})", ep.port, ep.slot);
                let location = nic.free_location(dev).map_err(|e| {
                    setup_err(
                        dev,
                        Some(tag.clone()),
                        format!("cannot find a free rule location: {e}"),
                        "free a steering rule slot or check the NIC",
                    )
                })?;
                let rule = InstalledRule {
                    device: dev.clone(),
                    ifindex: *ifindex,
                    location,
                    slot: ep.slot,
                    spec,
                };
                rec.put(&rule)
                    .map_err(|e| rule_err(&rule, "cannot record the rule", &e))?;
                if let Err(e) = nic.insert_rule_at(dev, location, &rule.spec) {
                    let mut reason =
                        format!("cannot insert steering rule at location {location}: {e}");
                    if let Err(re) = rec.remove(&rule) {
                        reason.push_str(&format!("; dropping its record entry also failed: {re}"));
                    }
                    return Err(setup_err(
                        dev,
                        Some(tag),
                        reason,
                        "free the location or check that the rule table has room; if the error names a driver failure, check `ethtool -k <dev>` for ntuple support",
                    ));
                }
                done.push(rule);
            }
        }
    }
    Ok(())
}

pub(crate) fn uninstall(
    nic: &dyn NicOps,
    rec: &mut dyn RecordStore,
    rules: &[InstalledRule],
) -> Result<(), XdpError> {
    let mut first = None;
    for r in rules {
        if let Err(e) = remove_one(nic, rec, r) {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

pub(crate) fn reap(nic: &dyn NicOps, rec: &mut dyn RecordStore) -> Result<usize, XdpError> {
    let entries = rec.all().map_err(|e| {
        setup_err(
            "steering record",
            None,
            format!("cannot read the steering record: {e}"),
            "check the record directory",
        )
    })?;
    let mut deleted = 0usize;
    for r in &entries {
        if remove_one(nic, rec, r)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub(crate) fn verify(nic: &dyn NicOps, rules: &[InstalledRule]) -> Result<(), XdpError> {
    verify_classified(nic, rules).map_err(|e| match e {
        RuleCheck::Unreadable { device, error } => {
            io_err(&device, "cannot re-read the steering rules", &error)
        }
        RuleCheck::Breach(e) => e,
    })
}

#[derive(Debug)]
pub(crate) enum RuleCheck {
    Unreadable { device: String, error: io::Error },
    Breach(XdpError),
}

pub(crate) fn verify_classified(
    nic: &dyn NicOps,
    rules: &[InstalledRule],
) -> Result<(), RuleCheck> {
    let devices: BTreeSet<&str> = rules.iter().map(|r| r.device.as_str()).collect();
    for dev in devices {
        let current = nic.rules(dev).map_err(|error| RuleCheck::Unreadable {
            device: dev.to_string(),
            error,
        })?;
        let mine: Vec<&InstalledRule> = rules.iter().filter(|r| r.device == dev).collect();
        for r in &mine {
            let found = current
                .iter()
                .any(|c| c.location == r.location && c.as_ours().as_ref() == Some(&r.spec));
            if !found {
                return Err(RuleCheck::Breach(setup_err(
                    dev,
                    Some(label(r)),
                    format!(
                        "steering rule at location {} is missing or changed",
                        r.location
                    ),
                    "another tool changed the NIC rules; stop it and restart the service",
                )));
            }
        }
        let our_locations: BTreeSet<u32> = mine.iter().map(|r| r.location).collect();
        let our_queues: BTreeSet<u32> = mine.iter().map(|r| r.spec.queue).collect();
        for c in current
            .iter()
            .filter(|c| !our_locations.contains(&c.location))
        {
            if let Some(q) = c.queues().into_iter().find(|q| our_queues.contains(q)) {
                let r = mine
                    .iter()
                    .find(|r| r.spec.queue == q)
                    .copied()
                    .unwrap_or(mine[0]);
                return Err(RuleCheck::Breach(setup_err(
                    dev,
                    Some(label(r)),
                    format!(
                        "queue {q} is also used by the foreign rule at location {}",
                        c.location
                    ),
                    "stop the other user of the queue and restart the service",
                )));
            }
        }
    }
    Ok(())
}

pub(crate) const BUSY_RETRY: Duration = Duration::from_millis(200);
pub(crate) const BUSY_STEP: Duration = Duration::from_millis(10);

pub(crate) fn queues_unbound(nic: &dyn NicOps, rules: &[InstalledRule]) -> Result<(), XdpError> {
    queues_unbound_with(nic, rules, &mut std::thread::sleep)
}

pub(crate) fn queues_unbound_with(
    nic: &dyn NicOps,
    rules: &[InstalledRule],
    sleep: &mut dyn FnMut(Duration),
) -> Result<(), XdpError> {
    let pairs: BTreeSet<(&str, u32)> = rules
        .iter()
        .map(|r| (r.device.as_str(), r.spec.queue))
        .collect();
    let retries = BUSY_RETRY.as_millis() / BUSY_STEP.as_millis();
    for (dev, q) in pairs {
        let probe = || {
            nic.queue_has_xsk(dev, q)
                .map_err(|e| io_err(dev, &format!("cannot probe queue {q}"), &e))
        };
        let mut bound = probe()?;
        let mut tries = 0;
        while bound && tries < retries {
            sleep(BUSY_STEP);
            tries += 1;
            bound = probe()?;
        }
        if bound {
            let r = rules.iter().find(|r| r.device == dev && r.spec.queue == q);
            return Err(setup_err(
                dev,
                r.map(label),
                format!("an AF_XDP socket is already bound to queue {q}"),
                "stop the other XDP user and restart the service",
            ));
        }
    }
    Ok(())
}
