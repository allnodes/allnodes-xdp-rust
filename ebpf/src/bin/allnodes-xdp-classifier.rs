// SPDX-License-Identifier: Apache-2.0
//
// The receive classifier: redirects IPv4/UDP packets whose destination an owner
// registered in `OWNED` to that owner's AF_XDP socket on the receiving queue, and
// passes everything else to the kernel. An owned packet on a queue where its owner
// has no socket is dropped and counted, or passed, as the owner chose. Derived from the XDP program of Agave's
// `xdp-ebpf` crate (https://github.com/anza-xyz/agave, Apache-2.0); changed by
// Allnodes in 2026.
#![no_std]
#![no_main]

#[path = "../shared.rs"]
mod shared;

use {
    aya_ebpf::{
        bindings::xdp_action::{XDP_DROP, XDP_PASS},
        helpers::generated::bpf_xdp_get_buff_len,
        macros::{map, xdp},
        maps::{HashMap, PerCpuArray, XskMap},
        programs::XdpContext,
    },
    core::ptr,
    shared::{ANY_IP, MAX_QUEUES, MAX_SLOTS, owned_key, owned_slot, passes_on_miss, xsk_index},
};

#[unsafe(no_mangle)]
// Set to 1 from user space at load time to drop multi-frag packets (i40e).
static DROP_MULTI_FRAGS: u8 = 0;

#[map]
static OWNED: HashMap<u64, u32> = HashMap::with_max_entries(64, 0);

#[map]
static XSKS: XskMap = XskMap::with_max_entries(MAX_SLOTS * MAX_QUEUES, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPV4_MIN_HLEN: usize = 20;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn allnodes_xdp_rx(ctx: XdpContext) -> u32 {
    if drop_frags() && has_frags(&ctx) {
        return XDP_DROP;
    }
    try_rx(&ctx).unwrap_or(XDP_PASS)
}

#[inline]
fn drop_frags() -> bool {
    // SAFETY: only modified at load time; volatile keeps the compiler from folding it.
    unsafe { ptr::read_volatile(&DROP_MULTI_FRAGS) == 1 }
}

#[inline]
fn has_frags(ctx: &XdpContext) -> bool {
    let linear_len = ctx.data_end() - ctx.data();
    // SAFETY: the verifier guarantees ctx.ctx is valid.
    let buf_len = unsafe { bpf_xdp_get_buff_len(ctx.ctx) as usize };
    linear_len < buf_len
}

#[inline]
fn try_rx(ctx: &XdpContext) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + ETH_HLEN > data_end {
        return None;
    }
    let h_proto = u16::from_be(unsafe { *((data + 12) as *const u16) });
    if h_proto != ETH_P_IP {
        return None;
    }

    let ip = data + ETH_HLEN;
    if ip + IPV4_MIN_HLEN > data_end {
        return None;
    }
    let ihl = (unsafe { *(ip as *const u8) } & 0x0f) as usize * 4;
    if ihl < IPV4_MIN_HLEN {
        return None;
    }
    if unsafe { *((ip + 9) as *const u8) } != IPPROTO_UDP {
        return None;
    }
    let frag_off = u16::from_be(unsafe { *((ip + 6) as *const u16) });
    if frag_off & 0x3fff != 0 {
        return None;
    }

    let udp = ip + ihl;
    if udp + 8 > data_end {
        return None;
    }
    let dst_ip = unsafe { *((ip + 16) as *const u32) };
    let dport = u16::from_be(unsafe { *((udp + 2) as *const u16) });

    // An owner of the exact address wins over one of the port on every address.
    let owner = match unsafe { OWNED.get(&owned_key(dst_ip, dport)) } {
        Some(value) => *value,
        None => *unsafe { OWNED.get(&owned_key(ANY_IP, dport)) }?,
    };
    let slot = owned_slot(owner);
    let miss = || {
        if passes_on_miss(owner) {
            XDP_PASS
        } else {
            count_drop()
        }
    };

    let queue = unsafe { (*ctx.ctx).rx_queue_index };
    if slot >= MAX_SLOTS || queue >= MAX_QUEUES {
        return Some(miss());
    }
    Some(XSKS.redirect(xsk_index(slot, queue), 0).unwrap_or_else(|_| miss()))
}

#[inline]
fn count_drop() -> u32 {
    if let Some(counter) = STATS.get_ptr_mut(0) {
        unsafe { *counter += 1 };
    }
    XDP_DROP
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // An infinite loop makes the verifier refuse the program if it can ever panic.
    loop {}
}
