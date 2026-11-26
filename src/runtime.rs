
use {
    crate::{
        add_rx_port, bond,
        device::NetworkDevice,
        classifier::{self, Miss, SHARED_SLOT},
        dispatcher::{self, AdoptedMember, AttachMode, BpffsLock, Dispatcher, Incumbent},
        load_rx_program, register_xsk,
    },
    aya::Ebpf,
    std::{
        error::Error,
        os::fd::{AsFd, RawFd},
        sync::{Mutex, OnceLock},
    },
};

static INSTALLED: OnceLock<Mutex<XdpRuntime>> = OnceLock::new();

pub fn add_installed_rx_port(port: u16) -> Result<(), Box<dyn Error>> {
    let Some(runtime) = INSTALLED.get() else {
        return Err("no XDP runtime is installed".into());
    };
    runtime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .add_rx_port(port)
}

enum Attachment {
    Exclusive(Ebpf),
    Chained(Dispatcher),
    Adopted(AdoptedMember),
}

impl Attachment {
    fn add_rx_port(&mut self, port: u16) -> Result<(), Box<dyn Error>> {
        match self {
            Attachment::Exclusive(ebpf) => add_rx_port(ebpf, port),
            Attachment::Chained(dispatcher) => add_rx_port(dispatcher.our_member_mut()?, port),
            Attachment::Adopted(member) => Ok(classifier::pinned::own_port(
                member.owned.as_fd(),
                port,
                SHARED_SLOT,
                Miss::Pass,
            )?),
        }
    }

    fn register_xsk(&mut self, queue: u32, fd: RawFd) -> Result<(), Box<dyn Error>> {
        match self {
            Attachment::Exclusive(ebpf) => register_xsk(ebpf, queue, fd),
            Attachment::Chained(dispatcher) => {
                register_xsk(dispatcher.our_member_mut()?, queue, fd)
            }
            Attachment::Adopted(member) => Ok(classifier::pinned::register_queue_xsk(
                member.xsks.as_fd(),
                SHARED_SLOT,
                queue,
                fd,
            )?),
        }
    }
}

struct Device {
    device: NetworkDevice,
    attach: Attachment,
}

impl Drop for Device {
    fn drop(&mut self) {
        let Attachment::Chained(dispatcher) = &mut self.attach else {
            return;
        };
        let left = BpffsLock::acquire().and_then(|lock| dispatcher.leave_in_place(&self.device, &lock));
        if let Err(e) = left {
            tracing::debug!(
                device = %self.device.name(),
                error = %e,
                "xdp: leaving the dispatcher chain on drop failed; the next start removes the member"
            );
        }
    }
}

pub struct XdpRuntime {
    devices: Vec<Device>,
}

impl XdpRuntime {
    pub fn new(
        interface: &str,
        require_native: bool,
        chain_loading: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let names = resolve_devices(interface)?;
        let mut devices = Vec::with_capacity(names.len());
        for name in names {
            let device = NetworkDevice::new(&name)?;
            let attach = if chain_loading {
                Attachment::Chained(chain(&device, require_native)?)
            } else {
                attach_exclusive(&device, require_native)?
            };
            devices.push(Device { device, attach });
        }
        Ok(Self { devices })
    }

    pub fn adopt(interface: &str, members: Vec<AdoptedMember>) -> Result<Self, Box<dyn Error>> {
        let names = resolve_devices(interface)?;
        if names.len() != members.len() {
            return Err(format!(
                "{interface} resolved to {} device(s) but {} member(s) were claimed",
                names.len(),
                members.len()
            )
            .into());
        }
        let devices = names
            .into_iter()
            .zip(members)
            .map(|(name, member)| {
                let device = NetworkDevice::new(&name)?;
                tracing::warn!(
                    "xdp: taking over the XDP program an earlier run left on {name} (member id \
                     {}), because this process was not granted the capabilities to load one of \
                     its own. Grant them and restart to have it install its own program",
                    member.prog_id
                );
                Ok(Device {
                    device,
                    attach: Attachment::Adopted(member),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        Ok(Self { devices })
    }

    pub const fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn device(&self, idx: usize) -> &NetworkDevice {
        &self.devices[idx].device
    }

    pub fn add_rx_port(&mut self, port: u16) -> Result<(), Box<dyn Error>> {
        for dev in &mut self.devices {
            dev.attach.add_rx_port(port)?;
        }
        Ok(())
    }

    pub fn register_xsk(&mut self, idx: usize, queue: u32, fd: RawFd) -> Result<(), Box<dyn Error>> {
        self.devices[idx].attach.register_xsk(queue, fd)
    }

    pub fn abandon_presence(&mut self) {
        for device in &mut self.devices {
            if let Attachment::Chained(dispatcher) = &mut device.attach {
                dispatcher.abandon_presence();
            }
        }
    }

    pub fn hold_for_process(self) -> Result<(), Box<dyn Error>> {
        if INSTALLED.set(Mutex::new(self)).is_err() {
            return Err("an XDP runtime is already installed in this process".into());
        }
        Ok(())
    }
}


pub fn claim_adoptable(interface: &str) -> Option<Vec<AdoptedMember>> {
    let names = resolve_devices(interface).ok()?;
    if names.is_empty() {
        return None;
    }
    let mut members = Vec::with_capacity(names.len());
    for name in &names {
        let device = NetworkDevice::new(name).ok()?;
        let member = dispatcher::adoptable(&device)?;
        classifier::pinned::disarm(member.owned.as_fd()).ok()?;
        members.push(member);
    }
    Some(members)
}

fn chain(device: &NetworkDevice, require_native: bool) -> Result<Dispatcher, Box<dyn Error>> {
    let lock = BpffsLock::acquire()?;
    dispatcher::attach_or_join(device, attach_mode(require_native), &lock)
}

const fn attach_mode(require_native: bool) -> AttachMode {
    if require_native {
        AttachMode::Native
    } else {
        AttachMode::NativeOrGeneric
    }
}

pub enum Outlook {
    Exclusive,
    Chained,
    NeedsHookSharing(String),
    Blocked(String),
}

pub fn plan_attach(
    interface: &str,
    chain_loading: bool,
    may_chain: bool,
) -> Result<Outlook, Box<dyn Error>> {
    if chain_loading && !may_chain {
        return Ok(Outlook::NeedsHookSharing(
            "chain loading was asked for".to_string(),
        ));
    }
    let mut sharing = chain_loading;
    for name in resolve_devices(interface)? {
        let device = NetworkDevice::new(&name)?;
        if chain_loading {
            continue;
        }
        match dispatcher::classify(&device)? {
            Incumbent::Free | Incumbent::OurLeftover(_) => {}
            Incumbent::LiveSibling(attachment) => {
                if !may_chain {
                    return Ok(Outlook::NeedsHookSharing(format!(
                        "{name} is already in use by another process sharing it through the XDP \
                         dispatcher (id {})",
                        attachment.prog_id
                    )));
                }
                sharing = true;
            }
            Incumbent::ForeignDispatcher(attachment) => {
                return Ok(Outlook::Blocked(format!(
                    "{name} already carries an XDP dispatcher (id {}) whose programs are not \
                     ours. Enable chain loading to join that chain deliberately",
                    attachment.prog_id
                )));
            }
            Incumbent::Opaque(prog_id) => {
                return Ok(Outlook::Blocked(format!(
                    "{name} already has an XDP program attached (id {prog_id}) that is not a \
                     libxdp dispatcher, so nothing can be chained onto it and it is not ours to \
                     remove"
                )));
            }
            Incumbent::Unreadable(prog_id) => {
                return Ok(Outlook::Blocked(format!(
                    "{name} has an XDP program attached (id {prog_id}) and /sys/fs/bpf is not \
                     readable by this process (mode 700, root-owned), so whether it is a leftover \
                     of ours cannot be told. `install -d -o <user> /sys/fs/bpf/xdp` would let it \
                     be recognized and cleaned up"
                )));
            }
        }
    }
    Ok(if sharing { Outlook::Chained } else { Outlook::Exclusive })
}

fn attach_exclusive(
    device: &NetworkDevice,
    require_native: bool,
) -> Result<Attachment, Box<dyn Error>> {
    for _ in 0..2 {
        match attach_exclusive_once(device, require_native) {
            Err(err) if is_stale_classification(err.as_ref()) => {
                tracing::debug!("xdp: {} changed while being taken; deciding again", device.name());
            }
            result => return result,
        }
    }
    attach_exclusive_once(device, require_native)
}

fn is_stale_classification(err: &dyn Error) -> bool {
    err.to_string().contains(dispatcher::CHANGED_UNDER_US)
}

fn attach_exclusive_once(
    device: &NetworkDevice,
    require_native: bool,
) -> Result<Attachment, Box<dyn Error>> {
    match dispatcher::classify(device)? {
        Incumbent::Free => Ok(Attachment::Exclusive(load_rx_program(device, require_native)?)),
        Incumbent::OurLeftover(attachment) => {
            tracing::warn!(
                "xdp: {} still carries an XDP program of ours (id {}) left by a previous run — \
                 a chain-loaded attachment belongs to the interface, not to the process that \
                 made it, so it outlives both a crash and a clean stop. Removing it and taking \
                 the hook",
                device.name(),
                attachment.prog_id
            );
            let lock = BpffsLock::acquire()?;
            dispatcher::remove_leftover(device, &attachment, &lock)?;
            drop(lock);
            Ok(Attachment::Exclusive(load_rx_program(device, require_native)?))
        }
        Incumbent::LiveSibling(attachment) => {
            tracing::warn!(
                "xdp: another process is already using {} through an XDP dispatcher (id {}), \
                 so this one is chain-loading beside it rather than taking the hook exclusively. \
                 Enable chain loading to ask for that deliberately; if nothing should be sharing \
                 the interface, stop the other process first",
                device.name(),
                attachment.prog_id
            );
            Ok(Attachment::Chained(chain(device, require_native)?))
        }
        Incumbent::ForeignDispatcher(attachment) => Err(format!(
            "{name} already carries an XDP dispatcher (id {id}) whose programs are not ours. \
             Running beside it is what chain loading is for — enable it to join that chain \
             deliberately, and note that a program ahead of ours in it can stop packets before \
             they reach us. To have the interface to ourselves instead, detach that program with \
             `ip link set dev {name} xdp off`",
            name = device.name(),
            id = attachment.prog_id,
        )
        .into()),
        Incumbent::Opaque(_) => Ok(Attachment::Exclusive(load_rx_program(device, require_native)?)),
        Incumbent::Unreadable(prog_id) => Err(format!(
            "{name} has an XDP program attached (id {prog_id}), and /sys/fs/bpf cannot be read to \
             tell whether it is one of ours: it is mode 700 and owned by root as systemd mounts \
             it. Give the pin directory to the user the service runs as (`install -d -o <user> \
             /sys/fs/bpf/xdp`) so a leftover of ours can be recognized, or detach the program \
             with `ip link set dev {name} xdp off` if nothing should be on that interface",
            name = device.name(),
        )
        .into()),
    }
}

fn resolve_devices(interface: &str) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(bond::physical_devices(interface)?)
}
