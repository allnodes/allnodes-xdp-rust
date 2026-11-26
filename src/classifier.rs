
use {
    crate::error::XdpError,
    aya::{
        Ebpf,
        maps::{HashMap, MapData, PerCpuArray, XskMap},
    },
    std::{collections::HashMap as StdHashMap, io, net::Ipv4Addr, os::fd::RawFd},
};

const BPF_EXIST: u64 = 2;

#[path = "../ebpf/src/shared.rs"]
mod shared;

pub(crate) use shared::{MAX_QUEUES, MAX_SLOTS, xsk_index};
use shared::owned_value;

pub(crate) const OWNED_MAP: &str = "OWNED";
pub(crate) const OWNED_CAPACITY: usize = 64;
pub(crate) const XSKS_MAP: &str = "XSKS";
pub(crate) const STATS_MAP: &str = "STATS";

pub(crate) const fn owned_key(ip: Ipv4Addr, port: u16) -> u64 {
    shared::owned_key(u32::from_ne_bytes(ip.octets()), port)
}

pub(crate) struct Classifier {
    interface: String,
    owned: HashMap<MapData, u64, u32>,
    xsks: XskMap<MapData>,
    stats: PerCpuArray<MapData, u64>,
    registered: StdHashMap<u32, (u32, u32, RawFd)>,
}

impl Classifier {
    pub(crate) fn from_member(interface: &str, ebpf: &mut Ebpf) -> Result<Self, XdpError> {
        let take = |ebpf: &mut Ebpf, name: &str| {
            ebpf.take_map(name).ok_or_else(|| {
                setup(
                    interface,
                    format!("the classifier object has no {name} map"),
                )
            })
        };
        let owned = take(ebpf, OWNED_MAP)?;
        let xsks = take(ebpf, XSKS_MAP)?;
        let stats = take(ebpf, STATS_MAP)?;
        let wrong = |name: &str, e: aya::maps::MapError| {
            setup(
                interface,
                format!("the classifier {name} map has an unexpected type: {e}"),
            )
        };
        Ok(Self {
            interface: interface.to_string(),
            owned: HashMap::try_from(owned).map_err(|e| wrong(OWNED_MAP, e))?,
            xsks: XskMap::try_from(xsks).map_err(|e| wrong(XSKS_MAP, e))?,
            stats: PerCpuArray::try_from(stats).map_err(|e| wrong(STATS_MAP, e))?,
            registered: StdHashMap::new(),
        })
    }

    pub(crate) fn own(
        &mut self,
        ip: Ipv4Addr,
        port: u16,
        slot: u32,
        miss: Miss,
    ) -> Result<(), XdpError> {
        if slot >= MAX_SLOTS {
            return Err(self.err(format!(
                "slot {slot} is out of range (at most {MAX_SLOTS} slots)"
            )));
        }
        self.owned
            .insert(owned_key(ip, port), miss.owned_value(slot), 0)
            .map_err(|e| self.err(format!("cannot own {ip}:{port} in the classifier: {e}")))
    }

    pub(crate) fn disown(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), XdpError> {
        self.owned
            .remove(&owned_key(ip, port))
            .map_err(|e| self.err(format!("cannot disown {ip}:{port} in the classifier: {e}")))
    }

    pub(crate) fn register_xsk(
        &mut self,
        slot: u32,
        queue: u32,
        fd: RawFd,
    ) -> Result<(), XdpError> {
        if slot >= MAX_SLOTS || queue >= MAX_QUEUES {
            return Err(self.err(format!(
                "slot {slot} / queue {queue} is out of range (at most {MAX_SLOTS} slots and \
                 {MAX_QUEUES} queues)"
            )));
        }
        let index = xsk_index(slot, queue);
        self.xsks.set(index, fd, 0).map_err(|e| {
            self.err(format!(
                "cannot register the socket of slot {slot} queue {queue}: {e}"
            ))
        })?;
        self.registered.insert(index, (slot, queue, fd));
        Ok(())
    }

    pub(crate) fn forget_xsk(&mut self, slot: u32, queue: u32) {
        self.registered.remove(&xsk_index(slot, queue));
    }

    pub(crate) fn unregister_xsk(&mut self, slot: u32, queue: u32) -> Result<(), XdpError> {
        let index = xsk_index(slot, queue);
        self.xsks.unset(index).map_err(|e| {
            self.err(format!(
                "cannot unregister the socket of slot {slot} queue {queue}: {e}"
            ))
        })?;
        self.registered.remove(&index);
        Ok(())
    }

    pub(crate) fn registered(&self) -> Vec<(u32, u32)> {
        let mut v: Vec<(u32, u32)> = self.registered.values().map(|(s, q, _)| (*s, *q)).collect();
        v.sort_unstable();
        v
    }

    pub(crate) fn xsk_in_map(&mut self, slot: u32, queue: u32) -> io::Result<Option<bool>> {
        let index = xsk_index(slot, queue);
        let Some(&(_, _, fd)) = self.registered.get(&index) else {
            return Ok(None);
        };
        match self.xsks.set(index, fd, BPF_EXIST) {
            Ok(()) => Ok(Some(true)),
            Err(aya::maps::MapError::SyscallError(e)) => match e.io_error.raw_os_error() {
                Some(libc::ENOENT | libc::EBADF | libc::ENOTSOCK | libc::EOPNOTSUPP) => {
                    Ok(Some(false))
                }
                _ => Err(e.io_error),
            },
            Err(e) => Err(io::Error::other(e)),
        }
    }

    pub(crate) fn no_socket_drops(&self) -> io::Result<u64> {
        match self.stats.get(&0, 0) {
            Ok(values) => Ok(values.iter().copied().fold(0u64, u64::saturating_add)),
            Err(aya::maps::MapError::SyscallError(e)) => Err(e.io_error),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn err(&self, reason: String) -> XdpError {
        setup(&self.interface, reason)
    }
}

pub const SHARED_SLOT: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    Pass,
    Drop,
}

impl Miss {
    const fn owned_value(self, slot: u32) -> u32 {
        owned_value(slot, matches!(self, Self::Pass))
    }
}

pub(crate) const fn any_address_key(port: u16) -> u64 {
    shared::owned_key(shared::ANY_IP, port)
}

pub fn own_port(
    ebpf: &mut Ebpf,
    port: u16,
    slot: u32,
    miss: Miss,
) -> Result<(), Box<dyn std::error::Error>> {
    if slot >= MAX_SLOTS {
        return Err(format!("slot {slot} is out of range (at most {MAX_SLOTS} slots)").into());
    }
    let map = ebpf.map_mut(OWNED_MAP).ok_or("the classifier object has no OWNED map")?;
    let mut owned: HashMap<_, u64, u32> = HashMap::try_from(map)?;
    owned.insert(any_address_key(port), miss.owned_value(slot), 0)?;
    Ok(())
}

pub fn register_queue_xsk(
    ebpf: &mut Ebpf,
    slot: u32,
    queue: u32,
    fd: RawFd,
) -> Result<(), Box<dyn std::error::Error>> {
    if slot >= MAX_SLOTS || queue >= MAX_QUEUES {
        return Err(format!(
            "slot {slot} / queue {queue} is out of range (at most {MAX_SLOTS} slots and \
             {MAX_QUEUES} queues)"
        )
        .into());
    }
    let map = ebpf.map_mut(XSKS_MAP).ok_or("the classifier object has no XSKS map")?;
    let mut xsks = XskMap::try_from(map)?;
    xsks.set(xsk_index(slot, queue), fd, 0)?;
    Ok(())
}

pub mod pinned {
    use {
        super::{MAX_QUEUES, MAX_SLOTS, Miss, any_address_key, xsk_index},
        crate::bpf_sys,
        std::{
            io,
            os::fd::{BorrowedFd, RawFd},
        },
    };

    pub fn own_port(owned: BorrowedFd<'_>, port: u16, slot: u32, miss: Miss) -> io::Result<()> {
        if slot >= MAX_SLOTS {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "slot out of range"));
        }
        bpf_sys::map_update(
            owned,
            &any_address_key(port).to_ne_bytes(),
            &miss.owned_value(slot).to_ne_bytes(),
        )
    }

    pub fn register_queue_xsk(
        xsks: BorrowedFd<'_>,
        slot: u32,
        queue: u32,
        fd: RawFd,
    ) -> io::Result<()> {
        if slot >= MAX_SLOTS || queue >= MAX_QUEUES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "slot or queue out of range"));
        }
        bpf_sys::map_update(
            xsks,
            &xsk_index(slot, queue).to_ne_bytes(),
            &(fd as u32).to_ne_bytes(),
        )
    }

    pub fn disarm(owned: BorrowedFd<'_>) -> io::Result<()> {
        const KEY_LEN: usize = size_of::<u64>();
        let mut key = None;
        let mut keys = Vec::new();
        while let Some(next) = bpf_sys::map_next_key(owned, key.as_deref(), KEY_LEN)? {
            keys.push(next.clone());
            key = Some(next);
        }
        for key in keys {
            bpf_sys::map_delete(owned, &key)?;
        }
        Ok(())
    }
}

fn setup(interface: &str, reason: String) -> XdpError {
    XdpError::Setup {
        interface: interface.to_string(),
        device: None,
        endpoint: None,
        reason,
        remedy: "this is a bug in the classifier loader; report it with the object hash"
            .to_string(),
    }
}
