// Derived from Agave's `cpu-utils` crate (https://github.com/anza-xyz/agave, Apache-2.0);
// changed by Allnodes. See NOTICE.

use std::{io, mem, ops::Deref};

const CPU_SETSIZE: usize = libc::CPU_SETSIZE as usize;

/// Identifies a logical CPU (hardware thread) by its kernel-assigned ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuId(usize);

impl CpuId {
    pub fn new(cpu: usize) -> io::Result<Self> {
        if cpu < CPU_SETSIZE {
            Ok(Self(cpu))
        } else {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    }
}

impl Deref for CpuId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn set_cpu_affinity(
    thread_id: Option<libc::pid_t>,
    cpus: impl IntoIterator<Item = CpuId>,
) -> io::Result<()> {
    // safety: cpu_set_t is a POD type, zero-initialization is standard
    let mut cpu_set: libc::cpu_set_t = unsafe { mem::zeroed() };

    for cpu in cpus {
        // safety: CpuId values are constructed only after validating cpu < CPU_SETSIZE.
        unsafe { libc::CPU_SET(*cpu, &mut cpu_set) };
    }

    let tid = thread_id.unwrap_or(0);

    // safety: sched_setaffinity is safe with valid parameters
    let result =
        unsafe { libc::sched_setaffinity(tid, mem::size_of::<libc::cpu_set_t>(), &cpu_set) };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn cpu_affinity(thread_id: Option<libc::pid_t>) -> io::Result<Vec<CpuId>> {
    // safety: cpu_set_t is a POD type, zero-initialization is standard
    let mut cpu_set: libc::cpu_set_t = unsafe { mem::zeroed() };

    let tid = thread_id.unwrap_or(0);

    // safety: sched_getaffinity is safe with valid parameters
    let result =
        unsafe { libc::sched_getaffinity(tid, mem::size_of::<libc::cpu_set_t>(), &mut cpu_set) };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut cpus = Vec::new();
    for cpu in 0..CPU_SETSIZE {
        // safety: cpu < CPU_SETSIZE by construction
        if unsafe { libc::CPU_ISSET(cpu, &cpu_set) } {
            cpus.push(CpuId::new(cpu)?);
        }
    }

    Ok(cpus)
}
