
use std::{io, os::fd::RawFd, time::Duration};

pub(crate) const RECLAIM_BATCH: usize = 64;
pub(crate) const SERVICE_STEP: Duration = Duration::from_micros(50);

pub(crate) trait RxRing: Send {
    fn pop(&mut self) -> Option<(usize, usize)>;
    fn frame(&self, f: usize) -> &[u8];
    fn release(&mut self, f: usize);
    fn refill(&mut self) -> usize;
    fn fill_needs_wakeup(&self) -> bool;
    fn wake(&self) -> io::Result<()>;
}

pub(crate) trait TxRing: Send {
    fn reserve(&mut self) -> Option<usize>;
    fn frame_mut(&mut self, f: usize) -> &mut [u8];
    fn submit(&mut self, f: usize, len: usize);
    fn needs_wakeup(&self) -> bool;
    fn wake(&self) -> io::Result<()>;
    fn reclaim(&mut self, max: usize) -> usize;
}

pub(crate) trait RingProbe: Send + Sync {
    fn rx_pending(&self) -> bool;
    fn fill_wants_wakeup(&self) -> bool;
    fn completions_pending(&self) -> bool;
    fn tx_progress(&self) -> (u32, u32);
    fn fd(&self) -> RawFd;
    fn retire(&self);
}

impl<T: RxRing + ?Sized> RxRing for Box<T> {
    fn pop(&mut self) -> Option<(usize, usize)> {
        (**self).pop()
    }
    fn frame(&self, f: usize) -> &[u8] {
        (**self).frame(f)
    }
    fn release(&mut self, f: usize) {
        (**self).release(f);
    }
    fn refill(&mut self) -> usize {
        (**self).refill()
    }
    fn fill_needs_wakeup(&self) -> bool {
        (**self).fill_needs_wakeup()
    }
    fn wake(&self) -> io::Result<()> {
        (**self).wake()
    }
}

impl<T: TxRing + ?Sized> TxRing for Box<T> {
    fn reserve(&mut self) -> Option<usize> {
        (**self).reserve()
    }
    fn frame_mut(&mut self, f: usize) -> &mut [u8] {
        (**self).frame_mut(f)
    }
    fn submit(&mut self, f: usize, len: usize) {
        (**self).submit(f, len);
    }
    fn needs_wakeup(&self) -> bool {
        (**self).needs_wakeup()
    }
    fn wake(&self) -> io::Result<()> {
        (**self).wake()
    }
    fn reclaim(&mut self, max: usize) -> usize {
        (**self).reclaim(max)
    }
}

impl<T: RingProbe + ?Sized> RingProbe for Box<T> {
    fn rx_pending(&self) -> bool {
        (**self).rx_pending()
    }
    fn fill_wants_wakeup(&self) -> bool {
        (**self).fill_wants_wakeup()
    }
    fn completions_pending(&self) -> bool {
        (**self).completions_pending()
    }
    fn tx_progress(&self) -> (u32, u32) {
        (**self).tx_progress()
    }
    fn fd(&self) -> RawFd {
        (**self).fd()
    }
    fn retire(&self) {
        (**self).retire();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WakeOutcome {
    Retry,
    LinkDown,
    Fatal,
    Gone,
}

pub(crate) fn classify_wake_error(e: &io::Error) -> WakeOutcome {
    match e.raw_os_error() {
        Some(libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::EINTR) => WakeOutcome::Retry,
        Some(libc::ENETDOWN) => WakeOutcome::LinkDown,
        Some(libc::ENXIO | libc::ENODEV) => WakeOutcome::Gone,
        _ => WakeOutcome::Fatal,
    }
}

pub(crate) fn errno_name(e: &io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(libc::ENXIO) => "ENXIO",
        Some(libc::ENODEV) => "ENODEV",
        Some(libc::EBADF) => "EBADF",
        Some(libc::EINVAL) => "EINVAL",
        Some(libc::EFAULT) => "EFAULT",
        Some(libc::ENOTCONN) => "ENOTCONN",
        Some(libc::EOPNOTSUPP) => "EOPNOTSUPP",
        Some(libc::ENOMEM) => "ENOMEM",
        Some(libc::EPERM) => "EPERM",
        Some(libc::EAGAIN) => "EAGAIN",
        Some(libc::EBUSY) => "EBUSY",
        Some(libc::ENOBUFS) => "ENOBUFS",
        Some(libc::EINTR) => "EINTR",
        Some(libc::ENETDOWN) => "ENETDOWN",
        Some(_) => "errno",
        None => "not an OS error",
    }
}

#[cfg(target_os = "linux")]
pub(crate) use real::xdp_statistics;
#[cfg(target_os = "linux")]
pub(crate) use real::{XskProbe, XskRx, XskTx};
#[cfg(target_os = "linux")]
pub(crate) use real::{place_frame_memory, split};

#[cfg(target_os = "linux")]
mod real {
    use {
        super::{RingProbe, RxRing, TxRing},
        crate::{
            setup::BoundQueue,
            device::{RingMmap, RxFillRing, TxCompletionRing, mmap_ring},
            socket,
            umem::{Frame, OwnedUmem, OwnedUmemFrame, Umem},
        },
        std::{
            io, mem,
            os::fd::{AsFd, AsRawFd, RawFd},
            ptr, slice,
            sync::{
                Arc,
                atomic::{AtomicBool, AtomicU32, Ordering},
            },
        },
    };

    struct XskOwner {
        _socket: socket::Socket<OwnedUmem>,
        base: usize,
        len: usize,
        frame_size: usize,
    }

    unsafe impl Sync for XskOwner {}

    impl XskOwner {
        fn bytes(&self, at: usize, len: usize) -> Option<*mut u8> {
            (at.checked_add(len)? <= self.len).then(|| (self.base + at) as *mut u8)
        }
    }

    pub(crate) struct XskRx {
        fill: RxFillRing<OwnedUmemFrame>,
        ring: socket::RxRing,
        free: Vec<usize>,
        fd: RawFd,
        #[cfg(debug_assertions)]
        pool: Vec<bool>,
        owner: Arc<XskOwner>,
    }

    pub(crate) struct XskTx {
        ring: socket::TxRing<OwnedUmemFrame>,
        completion: TxCompletionRing,
        free: Vec<usize>,
        in_flight: usize,
        #[cfg(debug_assertions)]
        pool: Vec<bool>,
        owner: Arc<XskOwner>,
    }

    pub(crate) struct XskProbe {
        rx: Idx,
        fill: Idx,
        comp: Idx,
        tx: Idx,
        maps: Vec<RingMmap<u64>>,
        fd: RawFd,
    }

    #[derive(Clone, Copy)]
    struct Idx {
        producer: *const AtomicU32,
        consumer: *const AtomicU32,
        flags: *const AtomicU32,
    }

    static INERT: AtomicU32 = AtomicU32::new(0);

    impl Idx {
        const fn of(m: &RingMmap<u64>) -> Self {
            Self {
                producer: m.producer.cast_const(),
                consumer: m.consumer.cast_const(),
                flags: m.flags.cast_const(),
            }
        }

        const fn inert() -> Self {
            Self {
                producer: &raw const INERT,
                consumer: &raw const INERT,
                flags: &raw const INERT,
            }
        }
    }

    impl XskProbe {
        pub(crate) const fn inert() -> Self {
            Self {
                rx: Idx::inert(),
                fill: Idx::inert(),
                comp: Idx::inert(),
                tx: Idx::inert(),
                maps: Vec::new(),
                fd: -1,
            }
        }
    }

    unsafe impl Sync for XskProbe {}
    unsafe impl Send for XskProbe {}

    #[cfg(debug_assertions)]
    fn in_pool(pool: &[bool], f: usize, frame_size: usize) -> bool {
        f.is_multiple_of(frame_size) && pool.get(f / frame_size).copied().unwrap_or(false)
    }

    const fn chunk(f: usize, frame_size: usize) -> usize {
        f & !(frame_size - 1)
    }

    pub(crate) fn split(bound: BoundQueue) -> io::Result<(XskRx, XskTx, XskProbe)> {
        let BoundQueue {
            rx,
            tx,
            socket,
            queue,
            ..
        } = bound;
        let ring = rx.ring.ok_or_else(|| {
            io::Error::other(format!("queue {queue}: the socket has no receive ring"))
        })?;
        let tx_ring = tx.ring.ok_or_else(|| {
            io::Error::other(format!("queue {queue}: the socket has no transmit ring"))
        })?;
        let umem = socket.umem();
        let mut tx_free = Vec::with_capacity(umem.capacity());
        while let Some(f) = umem.reserve() {
            tx_free.push(f.offset().0);
        }
        let rx_frames = umem.capacity() - tx_free.len();
        #[cfg(debug_assertions)]
        let (rx_pool, tx_pool) = {
            let mut tx_pool = vec![false; umem.capacity()];
            for f in &tx_free {
                tx_pool[f / umem.frame_size()] = true;
            }
            (tx_pool.iter().map(|t| !t).collect::<Vec<bool>>(), tx_pool)
        };
        let fd = socket.as_fd().as_raw_fd();
        let offsets = mmap_offsets(fd)?;
        let owner = Arc::new(XskOwner {
            base: umem.as_ptr() as usize,
            len: umem.len(),
            frame_size: umem.frame_size(),
            _socket: socket,
        });
        let (prx, pfill, pcomp, ptx) = unsafe {
            (
                mmap_ring::<u64>(fd, 0, &offsets.rx, libc::XDP_PGOFF_RX_RING as u64)?,
                mmap_ring::<u64>(fd, 0, &offsets.fr, libc::XDP_UMEM_PGOFF_FILL_RING)?,
                mmap_ring::<u64>(fd, 0, &offsets.cr, libc::XDP_UMEM_PGOFF_COMPLETION_RING)?,
                mmap_ring::<u64>(fd, 0, &offsets.tx, libc::XDP_PGOFF_TX_RING as u64)?,
            )
        };
        Ok((
            XskRx {
                fill: rx.fill,
                ring,
                free: Vec::with_capacity(rx_frames),
                fd,
                #[cfg(debug_assertions)]
                pool: rx_pool,
                owner: Arc::clone(&owner),
            },
            XskTx {
                ring: tx_ring,
                completion: tx.completion,
                free: tx_free,
                in_flight: 0,
                #[cfg(debug_assertions)]
                pool: tx_pool,
                owner,
            },
            XskProbe {
                rx: Idx::of(&prx),
                fill: Idx::of(&pfill),
                comp: Idx::of(&pcomp),
                tx: Idx::of(&ptx),
                maps: vec![prx, pfill, pcomp, ptx],
                fd,
            },
        ))
    }

    fn mmap_offsets(fd: RawFd) -> io::Result<libc::xdp_mmap_offsets> {
        let mut off: libc::xdp_mmap_offsets = unsafe { mem::zeroed() };
        let mut len = size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_MMAP_OFFSETS,
                (&raw mut off).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(off)
    }

    impl RxRing for XskRx {
        #[inline]
        fn pop(&mut self) -> Option<(usize, usize)> {
            let d = match self.ring.read() {
                Some(d) => d,
                None => {
                    self.ring.sync(true);
                    self.ring.read()?
                }
            };
            Some((d.addr as usize, d.len as usize))
        }

        #[inline]
        fn frame(&self, f: usize) -> &[u8] {
            let o = &*self.owner;
            let end = chunk(f, o.frame_size) + o.frame_size;
            match end
                .checked_sub(f)
                .and_then(|len| o.bytes(f, len).map(|p| (p, len)))
            {
                Some((p, len)) => unsafe { slice::from_raw_parts(p.cast_const(), len) },
                None => &[],
            }
        }

        #[inline]
        fn release(&mut self, f: usize) {
            let c = chunk(f, self.owner.frame_size);
            #[cfg(debug_assertions)]
            debug_assert!(
                in_pool(&self.pool, c, self.owner.frame_size),
                "frame {c} is not in the receive pool"
            );
            self.free.push(c);
        }

        fn refill(&mut self) -> usize {
            self.ring.commit();
            self.fill.sync(false);
            let mut n = 0;
            while let Some(f) = self.free.pop() {
                if self.fill.write(OwnedUmemFrame::from_offset(f, 0)).is_err() {
                    self.free.push(f);
                    break;
                }
                n += 1;
            }
            if n > 0 {
                self.fill.commit();
            }
            n
        }

        #[inline]
        fn fill_needs_wakeup(&self) -> bool {
            self.fill.needs_wakeup()
        }

        fn wake(&self) -> io::Result<()> {
            let rc = unsafe {
                libc::recvfrom(
                    self.fd,
                    ptr::null_mut(),
                    0,
                    libc::MSG_DONTWAIT,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl TxRing for XskTx {
        #[inline]
        fn reserve(&mut self) -> Option<usize> {
            if self.ring.available() == 0 {
                self.ring.sync(false);
                if self.ring.available() == 0 {
                    return None;
                }
            }
            self.free.pop()
        }

        #[inline]
        fn frame_mut(&mut self, f: usize) -> &mut [u8] {
            let len = self.owner.frame_size;
            match self.owner.bytes(f, len) {
                Some(p) => unsafe { slice::from_raw_parts_mut(p, len) },
                None => &mut [],
            }
        }

        #[inline]
        fn submit(&mut self, f: usize, len: usize) {
            #[cfg(debug_assertions)]
            debug_assert!(
                in_pool(&self.pool, f, self.owner.frame_size),
                "frame {f} is not in the transmit pool"
            );
            match self.ring.write(OwnedUmemFrame::from_offset(f, len), 0) {
                Ok(()) => {
                    self.ring.commit();
                    self.in_flight += 1;
                }
                Err(socket::RingFull(frame)) => self.free.push(frame.offset().0),
            }
        }

        #[inline]
        fn needs_wakeup(&self) -> bool {
            self.ring.needs_wakeup()
        }

        fn wake(&self) -> io::Result<()> {
            self.ring.wake().map(|_| ())
        }

        fn reclaim(&mut self, max: usize) -> usize {
            self.completion.sync(false);
            let mut n = 0;
            while n < max {
                let Some(c) = self.completion.read() else {
                    break;
                };
                let c = chunk(c.0.0, self.owner.frame_size);
                #[cfg(debug_assertions)]
                debug_assert!(
                    in_pool(&self.pool, c, self.owner.frame_size),
                    "completed frame {c} is not in the transmit pool"
                );
                self.free.push(c);
                n += 1;
            }
            if n > 0 {
                self.completion.commit();
                self.in_flight = self.in_flight.saturating_sub(n);
            }
            n
        }
    }

    fn nonempty(m: &Idx) -> bool {
        unsafe { (*m.producer).load(Ordering::Acquire) != (*m.consumer).load(Ordering::Acquire) }
    }

    impl RingProbe for XskProbe {
        fn rx_pending(&self) -> bool {
            nonempty(&self.rx)
        }

        fn fill_wants_wakeup(&self) -> bool {
            let flagged = unsafe {
                (*self.fill.flags).load(Ordering::Acquire) & libc::XDP_RING_NEED_WAKEUP != 0
            };
            flagged && nonempty(&self.fill)
        }

        fn completions_pending(&self) -> bool {
            nonempty(&self.comp)
        }

        fn tx_progress(&self) -> (u32, u32) {
            unsafe {
                (
                    (*self.tx.producer).load(Ordering::Acquire),
                    (*self.comp.producer).load(Ordering::Acquire),
                )
            }
        }

        fn fd(&self) -> RawFd {
            self.fd
        }

        fn retire(&self) {
            for m in &self.maps {
                let p = unsafe {
                    libc::mmap(
                        m.mmap.cast_mut().cast(),
                        m.mmap_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if p == libc::MAP_FAILED {
                    tracing::error!(
                        operation = "replace_ring_mapping",
                        error = %io::Error::last_os_error(),
                        risk = "range may be unmapped (kernels before 6.12)",
                        leftover = "socket stays open",
                        "XDP socket ring mapping replace failed"
                    );
                }
            }
        }
    }

    pub(crate) fn xdp_statistics(fd: RawFd) -> io::Result<libc::xdp_statistics> {
        let mut st: libc::xdp_statistics = unsafe { mem::zeroed() };
        let mut len = size_of::<libc::xdp_statistics>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_STATISTICS,
                (&raw mut st).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    const MPOL_MF_MOVE: libc::c_uint = 1 << 1;
    static MBIND_LOGGED: AtomicBool = AtomicBool::new(false);

    fn numa_node(device: &str) -> Option<u32> {
        let s =
            std::fs::read_to_string(format!("/sys/class/net/{device}/device/numa_node")).ok()?;
        s.trim()
            .parse::<i32>()
            .ok()
            .and_then(|n| u32::try_from(n).ok())
    }

    pub(crate) fn place_frame_memory(mem: &[u8], device: &str) -> io::Result<()> {
        let (ptr, len) = (mem.as_ptr(), mem.len());
        if let Some(node) = numa_node(device) {
            let mut mask = [0u64; 16];
            let maxnode = mask.len() * 64;
            let moved = match mask.get_mut(node as usize / 64) {
                Some(w) => {
                    *w |= 1 << (node % 64);
                    let rc = unsafe {
                        libc::syscall(
                            libc::SYS_mbind,
                            ptr,
                            len,
                            libc::MPOL_PREFERRED,
                            mask.as_ptr(),
                            maxnode + 1,
                            MPOL_MF_MOVE,
                        )
                    };
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                }
                None => Err(io::Error::other(format!(
                    "NUMA node {node} is beyond {maxnode}"
                ))),
            };
            if let Err(e) = moved
                && !MBIND_LOGGED.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    device = %device,
                    numa_node = node,
                    operation = "mbind",
                    error = %e,
                    outcome = "skipped",
                    "XDP socket frame memory NUMA placement failed"
                );
            }
        }
        if unsafe { libc::mlock(ptr.cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
