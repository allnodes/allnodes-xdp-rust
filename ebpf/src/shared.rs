//! Definitions shared by the eBPF program and the loader (included by both).
// Each side uses its half of the `OWNED` value encoding: the loader writes it, the
// program reads it.
#![allow(dead_code)]

pub const MAX_SLOTS: u32 = 16;
pub const MAX_QUEUES: u32 = 256;

pub const fn xsk_index(slot: u32, queue: u32) -> u32 {
    slot * MAX_QUEUES + queue
}

/// The address an owner of a port on every local address is keyed under (0.0.0.0).
pub const ANY_IP: u32 = 0;

/// `ip_be` is the address as the bytes sit in the packet read as a native u32
/// (`u32::from_ne_bytes(octets)`); `port` is in host order.
pub const fn owned_key(ip_be: u32, port: u16) -> u64 {
    ((ip_be as u64) << 16) | port as u64
}

/// Set in an `OWNED` value: a packet of this owner that reaches a queue where the
/// owner has no socket goes to the kernel. Without it the packet is dropped and
/// counted in `STATS`.
pub const PASS_ON_MISS: u32 = 1 << 31;

/// The `OWNED` value for `slot`, passing or dropping on a miss.
pub const fn owned_value(slot: u32, pass_on_miss: bool) -> u32 {
    if pass_on_miss { slot | PASS_ON_MISS } else { slot }
}

/// The slot an `OWNED` value names.
pub const fn owned_slot(value: u32) -> u32 {
    value & !PASS_ON_MISS
}

/// Whether an `OWNED` value passes a miss to the kernel.
pub const fn passes_on_miss(value: u32) -> bool {
    value & PASS_ON_MISS != 0
}
