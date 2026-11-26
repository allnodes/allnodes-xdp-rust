
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::DropReason;

pub(crate) const HEADERS: usize = 42;
const ETH: usize = 14;
const IP: usize = 20;
const UDP: usize = 8;

#[derive(Debug)]
pub(crate) struct RxDatagram<'a> {
    pub src_mac: [u8; 6],
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub payload: &'a [u8],
}

pub(crate) struct TxHeader {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

const fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

fn ip_checksum(header: &[u8]) -> u16 {
    !fold(sum16(header, 0))
}

fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, udp_len: u16) -> u32 {
    let mut acc = sum16(&src.octets(), 0);
    acc = sum16(&dst.octets(), acc);
    acc + 17 + u32::from(udp_len)
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub(crate) fn parse(frame: &[u8]) -> Result<RxDatagram<'_>, DropReason> {
    if frame.len() < ETH + IP || be16(frame, 12) != 0x0800 {
        return Err(DropReason::Malformed);
    }
    let ip = &frame[ETH..];
    if ip[0] >> 4 != 4 {
        return Err(DropReason::Malformed);
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(be16(ip, 2));
    if ihl < IP || total > ip.len() || total < ihl + UDP {
        return Err(DropReason::Malformed);
    }
    if ip[9] != 17 || be16(ip, 6) & 0x3fff != 0 {
        return Err(DropReason::Malformed);
    }
    if ip_checksum(&ip[..ihl]) != 0 {
        return Err(DropReason::BadIpChecksum);
    }
    let udp = &ip[ihl..total];
    let udp_len = usize::from(be16(udp, 4));
    if udp_len != udp.len() {
        return Err(DropReason::Malformed);
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    if be16(udp, 6) != 0 {
        let acc = sum16(udp, pseudo_sum(src_ip, dst_ip, be16(udp, 4)));
        if fold(acc) != 0xffff {
            return Err(DropReason::BadUdpChecksum);
        }
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Ok(RxDatagram {
        src_mac,
        src: SocketAddrV4::new(src_ip, be16(udp, 0)),
        dst: SocketAddrV4::new(dst_ip, be16(udp, 2)),
        payload: &udp[UDP..],
    })
}

pub(crate) fn build(
    out: &mut [u8],
    h: &TxHeader,
    payload: &[u8],
    mtu: usize,
) -> Result<usize, DropReason> {
    let ip_total = IP + UDP + payload.len();
    let frame_len = ETH + ip_total;
    if ip_total > mtu || frame_len > out.len() || ip_total > usize::from(u16::MAX) {
        return Err(DropReason::Oversize);
    }
    let out = &mut out[..frame_len];
    out[0..6].copy_from_slice(&h.dst_mac);
    out[6..12].copy_from_slice(&h.src_mac);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut out[ETH..ETH + IP];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&[0, 0]);
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&h.src.ip().octets());
    ip[16..20].copy_from_slice(&h.dst.ip().octets());
    let c = ip_checksum(ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());

    let udp_len = (UDP + payload.len()) as u16;
    out[HEADERS..].copy_from_slice(payload);
    let udp = &mut out[ETH + IP..];
    udp[0..2].copy_from_slice(&h.src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&h.dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&[0, 0]);
    let acc = sum16(udp, pseudo_sum(*h.src.ip(), *h.dst.ip(), udp_len));
    let c = match !fold(acc) {
        0 => 0xffff,
        c => c,
    };
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    Ok(frame_len)
}
