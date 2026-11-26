
use std::{
    io, mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::fd::{AsRawFd, RawFd},
    ptr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Received {
    pub len: usize,
    pub src: SocketAddrV4,
    pub dst: Ipv4Addr,
    pub ifindex: u32,
    pub truncated: bool,
}

pub(crate) struct KernelSock {
    sock: UdpSocket,
}

#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

fn setopt(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl KernelSock {
    pub(crate) fn new(sock: UdpSocket) -> io::Result<Self> {
        sock.set_nonblocking(true)?;
        let fd = sock.as_raw_fd();
        setopt(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        setopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )?;
        Ok(Self {
            sock,
        })
    }

    pub(crate) fn retire(&self) -> io::Result<()> {
        let dummy = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if dummy < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { libc::dup3(dummy, self.fd(), libc::O_CLOEXEC) };
        let err = io::Error::last_os_error();
        unsafe { libc::close(dummy) };
        if rc < 0 {
            return Err(err);
        }
        Ok(())
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let mut src: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut cmsg = CmsgBuf([0; 64]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&raw mut src).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.0.as_mut_ptr().cast();
        msg.msg_controllen = cmsg.0.len() as _;
        let n = unsafe { libc::recvmsg(self.fd(), &raw mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock => Ok(None),
                _ => Err(e),
            };
        }
        let mut dst = Ipv4Addr::UNSPECIFIED;
        let mut ifindex = 0;
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
                    let info = ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::in_pktinfo>());
                    dst = Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr));
                    ifindex = info.ipi_ifindex as u32;
                }
                c = libc::CMSG_NXTHDR(&raw const msg, c);
            }
        }
        let src = SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr)),
            u16::from_be(src.sin_port),
        );
        Ok(Some(Received {
            len: (n as usize).min(buf.len()),
            src,
            dst,
            ifindex,
            truncated: msg.msg_flags & libc::MSG_TRUNC != 0,
        }))
    }

    pub(crate) fn send(
        &self,
        dst: SocketAddrV4,
        src: Option<Ipv4Addr>,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut to: libc::sockaddr_in = unsafe { mem::zeroed() };
        to.sin_family = libc::AF_INET as libc::sa_family_t;
        to.sin_port = dst.port().to_be();
        to.sin_addr.s_addr = u32::from(*dst.ip()).to_be();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut cmsg = CmsgBuf([0; 64]);
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&raw mut to).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        if let Some(src) = src.filter(|s| !s.is_unspecified()) {
            let space = unsafe { libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as u32) } as usize;
            msg.msg_control = cmsg.0.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&raw const msg);
                (*c).cmsg_level = libc::IPPROTO_IP;
                (*c).cmsg_type = libc::IP_PKTINFO;
                (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as _;
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from(src).to_be(),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                ptr::write_unaligned(libc::CMSG_DATA(c).cast::<libc::in_pktinfo>(), info);
            }
        }
        let n = unsafe { libc::sendmsg(self.fd(), &raw const msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
