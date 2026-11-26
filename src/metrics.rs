
use {
    crate::error::DropReason,
    std::{
        ops::Index,
        sync::atomic::{AtomicU64, Ordering::Relaxed},
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropCounts(pub [u64; DropReason::COUNT]);

impl Index<DropReason> for DropCounts {
    type Output = u64;

    fn index(&self, r: DropReason) -> &u64 {
        &self.0[r.index()]
    }
}

impl DropCounts {
    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpStatistics {
    /// Dropped for reasons other than an invalid descriptor (for example no fill frame).
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

impl XdpStatistics {
    #[cfg(target_os = "linux")]
    pub(crate) fn sum(all: &[libc::xdp_statistics]) -> Self {
        let mut t = Self::default();
        for s in all {
            t.rx_dropped += s.rx_dropped;
            t.rx_invalid_descs += s.rx_invalid_descs;
            t.tx_invalid_descs += s.tx_invalid_descs;
            t.rx_ring_full += s.rx_ring_full;
            t.rx_fill_ring_empty_descs += s.rx_fill_ring_empty_descs;
            t.tx_ring_empty_descs += s.tx_ring_empty_descs;
        }
        t
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketMetrics {
    pub rx_xdp: u64,
    pub tx_xdp: u64,
    pub kernel_served: u64,
    pub kernel_sent: u64,
    pub rx_dropped: DropCounts,
    pub tx_dropped: DropCounts,
    /// Not drops: quinn retries.
    pub tx_ring_full: u64,
    pub route_refresh_errors: u64,
}

/// Drops for a known endpoint (`InboxFull`) are in that socket's `rx_dropped`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PumpMetrics {
    pub delivered: u64,
    pub unknown_destination: u64,
    /// Includes receive wake-ups that found the link down.
    pub rx_dropped: DropCounts,
}

#[derive(Default)]
#[repr(align(128))]
struct Side {
    packets: AtomicU64,
    kernel: AtomicU64,
    full: AtomicU64,
    dropped: [AtomicU64; DropReason::COUNT],
}

impl Side {
    fn drops(&self) -> DropCounts {
        let mut out = [0; DropReason::COUNT];
        for (o, c) in out.iter_mut().zip(&self.dropped) {
            *o = c.load(Relaxed);
        }
        DropCounts(out)
    }
}

#[derive(Default)]
pub(crate) struct Metrics {
    rx: Side,
    tx: Side,
}

impl Metrics {
    #[inline]
    pub(crate) fn rx_xdp(&self, n: u64) {
        self.rx.packets.fetch_add(n, Relaxed);
    }

    #[inline]
    pub(crate) fn tx_xdp(&self) {
        self.tx.packets.fetch_add(1, Relaxed);
    }

    #[inline]
    pub(crate) fn kernel_served(&self) {
        self.rx.kernel.fetch_add(1, Relaxed);
    }

    #[inline]
    pub(crate) fn kernel_sent(&self) {
        self.tx.kernel.fetch_add(1, Relaxed);
    }

    #[inline]
    pub(crate) fn rx_drop(&self, r: DropReason) {
        self.rx.dropped[r.index()].fetch_add(1, Relaxed);
    }

    #[inline]
    pub(crate) fn tx_drop(&self, r: DropReason) {
        self.tx.dropped[r.index()].fetch_add(1, Relaxed);
    }

    #[cold]
    pub(crate) fn rx_dropped_of(&self, r: DropReason) -> u64 {
        self.rx.dropped[r.index()].load(Relaxed)
    }

    #[cold]
    pub(crate) fn tx_dropped_of(&self, r: DropReason) -> u64 {
        self.tx.dropped[r.index()].load(Relaxed)
    }

    #[cold]
    pub(crate) fn tx_ring_full(&self) {
        self.tx.full.fetch_add(1, Relaxed);
    }

    pub(crate) fn snapshot(&self) -> SocketMetrics {
        SocketMetrics {
            rx_xdp: self.rx.packets.load(Relaxed),
            tx_xdp: self.tx.packets.load(Relaxed),
            kernel_served: self.rx.kernel.load(Relaxed),
            kernel_sent: self.tx.kernel.load(Relaxed),
            rx_dropped: self.rx.drops(),
            tx_dropped: self.tx.drops(),
            tx_ring_full: self.tx.full.load(Relaxed),
            route_refresh_errors: 0,
        }
    }
}
