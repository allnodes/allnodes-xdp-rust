// Derived from Agave's `xdp` crate (https://github.com/anza-xyz/agave, Apache-2.0);
// changed by Allnodes. See NOTICE.
#![allow(clippy::arithmetic_side_effects)]

use {
    crate::ecn_codepoint::EcnCodepoint,
    libc::{ETH_P_IP, IPPROTO_UDP},
    std::net::Ipv4Addr,
};


pub const ETH_HEADER_SIZE: usize = 14;
/// Plain Ethernet header (14B) + 802.1Q tag (4B).
pub const VLAN_ETH_HEADER_SIZE: usize = ETH_HEADER_SIZE + 4;
pub const IP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
/// Total header size of an untagged IPv4 UDP frame: Ethernet + IP + UDP.
pub const PACKET_HEADER_SIZE: usize = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
/// Total header size of an 802.1Q tagged IPv4 UDP frame: tagged Ethernet + IP + UDP.
pub const VLAN_PACKET_HEADER_SIZE: usize = VLAN_ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
const IP_DONT_FRAGMENT: u16 = 0x4000;
/// EtherType identifying an 802.1Q tagged frame.
const ETH_P_8021Q: u16 = 0x8100;

pub fn write_eth_header(packet: &mut [u8], src_mac: &[u8; 6], dst_mac: &[u8; 6]) {
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(ETH_P_IP as u16).to_be_bytes());
}

/// Write an 18-byte Ethernet header carrying an 802.1Q VLAN tag.
///
/// Layout: `dst MAC (6) | src MAC (6) | TPID=0x8100 (2) | TCI (2) | inner EtherType (2)`.
/// The TCI packs `pcp` into the high 3 bits, DEI=0, and `vid` into the low 12 bits.
#[inline]
pub fn write_vlan_eth_header(
    packet: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    vid: u16,
    pcp: u8,
) {
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&ETH_P_8021Q.to_be_bytes());
    // TCI: PCP in the top 3 bits, then DEI=0 (frames are not marked drop-eligible, matching what
    // the kernel VLAN driver emits by default), then the VID in the low 12 bits.
    let tci = (((pcp as u16) & 0x7) << 13) | (vid & 0x0FFF);
    packet[14..16].copy_from_slice(&tci.to_be_bytes());
    packet[16..18].copy_from_slice(&(ETH_P_IP as u16).to_be_bytes());
}

/// Construct a complete untagged IPv4 UDP frame in `packet`.
///
/// Layout: `[Eth] [IPv4] [UDP] [payload]`. The caller is responsible for sizing `packet` to at
/// least `PACKET_HEADER_SIZE + payload.len()`; this function returns `false` and writes nothing
/// if the buffer is too small.
#[allow(clippy::too_many_arguments)]
pub fn construct_packet(
    packet: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ecn: Option<EcnCodepoint>,
) -> bool {
    let payload_len = payload.len();
    if packet.len() < PACKET_HEADER_SIZE + payload_len {
        return false;
    }
    // write the payload first as it's needed for checksum calculation (if enabled)
    packet[PACKET_HEADER_SIZE..PACKET_HEADER_SIZE + payload_len].copy_from_slice(payload);
    write_eth_header(packet, src_mac, dst_mac);
    write_ip_header_for_udp(
        &mut packet[ETH_HEADER_SIZE..],
        src_ip,
        dst_ip,
        ecn,
        (UDP_HEADER_SIZE + payload_len) as u16,
    );
    write_udp_header(
        &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        payload_len as u16,
        false,
    );
    true
}

/// Construct a complete VLAN-tagged IPv4 UDP frame in `packet`.
///
/// Layout: `[Eth + 802.1Q] [IPv4] [UDP] [payload]`. The caller is responsible for sizing `packet`
/// to at least `VLAN_PACKET_HEADER_SIZE + payload.len()`; this function returns `false` and
/// writes nothing if the buffer is too small.
#[allow(clippy::too_many_arguments)]
pub fn construct_vlan_packet(
    packet: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    vid: u16,
    pcp: u8,
    payload: &[u8],
    ecn: Option<EcnCodepoint>,
) -> bool {
    let payload_len = payload.len();
    if packet.len() < VLAN_PACKET_HEADER_SIZE + payload_len {
        return false;
    }
    // write the payload first as it's needed for checksum calculation (if enabled)
    packet[VLAN_PACKET_HEADER_SIZE..VLAN_PACKET_HEADER_SIZE + payload_len].copy_from_slice(payload);
    write_vlan_eth_header(packet, src_mac, dst_mac, vid, pcp);
    write_ip_header_for_udp(
        &mut packet[VLAN_ETH_HEADER_SIZE..],
        src_ip,
        dst_ip,
        ecn,
        (UDP_HEADER_SIZE + payload_len) as u16,
    );
    write_udp_header(
        &mut packet[VLAN_ETH_HEADER_SIZE + IP_HEADER_SIZE..],
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        payload_len as u16,
        false,
    );
    true
}

pub(crate) fn write_ip_header(
    packet: &mut [u8],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    payload_len: u16,
    protocol: u8,
    dont_fragment: bool,
    ttl: Option<u8>,
    tos: Option<u8>,
) {
    let total_len = IP_HEADER_SIZE + payload_len as usize;

    // version (4) and IHL (5)
    packet[0] = 0x45;
    // tos
    packet[1] = tos.unwrap_or(0);
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    // identification
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    // flags & frag offset
    let frag_flags = if dont_fragment { IP_DONT_FRAGMENT } else { 0 };
    packet[6..8].copy_from_slice(&frag_flags.to_be_bytes());
    packet[8] = ttl.unwrap_or(64);
    // protocol
    packet[9] = protocol;
    // checksum
    packet[10..12].copy_from_slice(&0u16.to_be_bytes());
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let checksum = calculate_ip_checksum(&packet[..IP_HEADER_SIZE]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Write IP header configured for UDP protocol
pub fn write_ip_header_for_udp(
    packet: &mut [u8],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    ecn: Option<EcnCodepoint>,
    payload_len: u16,
) {
    write_ip_header(
        packet,
        src_ip,
        dst_ip,
        payload_len,
        IPPROTO_UDP as u8,
        true,
        None,
        // tos is composed of DSCP (high 6 bits) and ECN (low 2 bits). We don't set DSCP bits, so
        // just set the ECN bits.
        ecn.map(|ecn| ecn as u8),
    );
}

pub fn write_udp_header(
    packet: &mut [u8],
    src_ip: &Ipv4Addr,
    src_port: u16,
    dst_ip: &Ipv4Addr,
    dst_port: u16,
    payload_len: u16,
    csum: bool,
) {
    let udp_len = UDP_HEADER_SIZE + payload_len as usize;

    packet[0..2].copy_from_slice(&src_port.to_be_bytes());
    packet[2..4].copy_from_slice(&dst_port.to_be_bytes());
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());

    if csum {
        let checksum = calculate_udp_checksum(&packet[..udp_len], src_ip, dst_ip);
        packet[6..8].copy_from_slice(&checksum.to_be_bytes());
    }
}

fn calculate_udp_checksum(udp_packet: &[u8], src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr) -> u16 {
    let udp_len = udp_packet.len();

    let mut sum: u32 = 0;

    let src_ip = src_ip.octets();
    let dst_ip = dst_ip.octets();

    sum += (u32::from(src_ip[0]) << 8) | u32::from(src_ip[1]);
    sum += (u32::from(src_ip[2]) << 8) | u32::from(src_ip[3]);
    sum += (u32::from(dst_ip[0]) << 8) | u32::from(dst_ip[1]);
    sum += (u32::from(dst_ip[2]) << 8) | u32::from(dst_ip[3]);
    sum += 17; // UDP
    sum += udp_len as u32;

    for i in 0..udp_len / 2 {
        // skip the checksum field
        if i * 2 == 6 {
            continue;
        }
        let word = ((udp_packet[i * 2] as u32) << 8) | (udp_packet[i * 2 + 1] as u32);
        sum += word;
    }

    if udp_len % 2 == 1 {
        sum += (udp_packet[udp_len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in 0..header.len() / 2 {
        let word = ((header[i * 2] as u32) << 8) | (header[i * 2 + 1] as u32);
        sum += word;
    }

    if header.len() % 2 == 1 {
        sum += (header[header.len() - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub struct UdpFrame<'a> {
    pub src: std::net::SocketAddrV4,
    pub dst: std::net::SocketAddrV4,
    pub payload: &'a [u8],
}

pub fn parse_udp_frame(frame: &[u8]) -> Option<UdpFrame<'_>> {
    if frame.len() < ETH_HEADER_SIZE {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP as u16 {
        return None;
    }

    let ip = &frame[ETH_HEADER_SIZE..];
    if ip.len() < IP_HEADER_SIZE || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < IP_HEADER_SIZE || ip.len() < ihl || ip[9] != IPPROTO_UDP as u8 {
        return None;
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let udp = &ip[ihl..];
    if udp.len() < UDP_HEADER_SIZE {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = (u16::from_be_bytes([udp[4], udp[5]]) as usize)
        .max(UDP_HEADER_SIZE)
        .min(udp.len());

    Some(UdpFrame {
        src: std::net::SocketAddrV4::new(src_ip, src_port),
        dst: std::net::SocketAddrV4::new(dst_ip, dst_port),
        payload: &udp[UDP_HEADER_SIZE..udp_len],
    })
}
