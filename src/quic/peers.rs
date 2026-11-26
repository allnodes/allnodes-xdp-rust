use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

pub(crate) const LOOKUP_TRIES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerPath {
    Xdp { mac: [u8; 6], slave: u8 },
    Kernel,
}

struct Slot {
    seq: AtomicU32,
    key: AtomicU64,
    val: AtomicU64,
}

pub(crate) struct PeerTable {
    slots: Box<[Slot]>,
}

const OCCUPIED: u64 = 1 << 48;
const TAG_XDP: u64 = 1 << 56;

fn key_of(peer: SocketAddrV4) -> u64 {
    OCCUPIED | (u64::from(u32::from(*peer.ip())) << 16) | u64::from(peer.port())
}

fn pack(path: PeerPath) -> u64 {
    match path {
        PeerPath::Kernel => 0,
        PeerPath::Xdp { mac, slave } => {
            let m = mac.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
            TAG_XDP | (u64::from(slave) << 48) | m
        }
    }
}

fn unpack(val: u64) -> PeerPath {
    if val & TAG_XDP == 0 {
        return PeerPath::Kernel;
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = (val >> (8 * (5 - i))) as u8;
    }
    PeerPath::Xdp {
        mac,
        slave: (val >> 48) as u8,
    }
}

impl PeerTable {
    pub(crate) fn new(slots_pow2: usize) -> Self {
        let n = slots_pow2.max(1).next_power_of_two();
        let slots = (0..n)
            .map(|_| Slot {
                seq: AtomicU32::new(0),
                key: AtomicU64::new(0),
                val: AtomicU64::new(0),
            })
            .collect();
        Self { slots }
    }

    #[inline]
    const fn hash(key: u64) -> u32 {
        (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u32
    }

    fn slot(&self, key: u64) -> &Slot {
        self.slot_at(Self::hash(key))
    }

    #[inline]
    fn slot_at(&self, h: u32) -> &Slot {
        &self.slots[(h as usize) & (self.slots.len() - 1)]
    }

    pub(crate) fn learn(&self, peer: SocketAddrV4, path: PeerPath) {
        let (key, val) = (key_of(peer), pack(path));
        let slot = self.slot(key);
        let seq = slot.seq.load(Ordering::Acquire);
        if seq & 1 == 1 {
            return;
        }
        if slot.key.load(Ordering::Relaxed) == key && slot.val.load(Ordering::Relaxed) == val {
            return;
        }
        if slot
            .seq
            .compare_exchange(
                seq,
                seq.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        fence(Ordering::Release);
        slot.key.store(key, Ordering::Relaxed);
        slot.val.store(val, Ordering::Relaxed);
        slot.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    #[inline]
    pub(crate) fn lookup_hashed(&self, peer: SocketAddrV4) -> (Option<PeerPath>, u32) {
        let key = key_of(peer);
        let h = Self::hash(key);
        let slot = self.slot_at(h);
        for _ in 0..LOOKUP_TRIES {
            let s1 = slot.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                continue;
            }
            let (k, v) = (
                slot.key.load(Ordering::Relaxed),
                slot.val.load(Ordering::Relaxed),
            );
            fence(Ordering::Acquire);
            if slot.seq.load(Ordering::Relaxed) != s1 {
                continue;
            }
            return ((k == key).then(|| unpack(v)), h);
        }
        (None, h)
    }
}
