
use {
    crate::{
        error::XdpError,
        installer::RecordStore,
        nic::{InstalledRule, RuleSpec},
        bpf_sys,
        dispatcher::BpffsLock,
    },
    std::{
        fs, io,
        net::Ipv4Addr,
        os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        path::{Path, PathBuf},
    },
};

const OWNER_PREFIX: &str = "gun-";
const MAP_PIN: &str = "record";
const MAP_NAME: &str = "record";
const MAP_CAPACITY: u32 = 1024;
const CREATE_ATTEMPTS: usize = 5;

const KEY_LEN: usize = 8;
const VALUE_LEN: usize = 16;
const V_IP: usize = 0;
const V_PORT: usize = 4;
const V_QUEUE: usize = 8;
const V_SLOT: usize = 12;
const _: () = assert!(V_PORT == V_IP + 4 && V_QUEUE == V_PORT + 2 + 2 && V_SLOT + 4 == VALUE_LEN);

#[derive(Debug, PartialEq, Eq)]
struct RawEntry {
    ifindex: u32,
    location: u32,
    spec: RuleSpec,
    slot: u32,
}

fn encode_key(ifindex: u32, location: u32) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    k[0..4].copy_from_slice(&ifindex.to_le_bytes());
    k[4..8].copy_from_slice(&location.to_le_bytes());
    k
}

fn encode_value(r: &InstalledRule) -> [u8; VALUE_LEN] {
    let mut v = [0u8; VALUE_LEN];
    v[V_IP..V_IP + 4].copy_from_slice(&u32::from(r.spec.dst_ip).to_le_bytes());
    v[V_PORT..V_PORT + 2].copy_from_slice(&r.spec.dst_port.to_le_bytes());
    v[V_QUEUE..V_QUEUE + 4].copy_from_slice(&r.spec.queue.to_le_bytes());
    v[V_SLOT..V_SLOT + 4].copy_from_slice(&r.slot.to_le_bytes());
    v
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn decode(key: &[u8], value: &[u8]) -> io::Result<RawEntry> {
    if key.len() != KEY_LEN || value.len() != VALUE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "record entry has sizes {}/{}, expected {KEY_LEN}/{VALUE_LEN}",
                key.len(),
                value.len()
            ),
        ));
    }
    Ok(RawEntry {
        ifindex: u32_at(key, 0),
        location: u32_at(key, 4),
        spec: RuleSpec {
            dst_ip: Ipv4Addr::from(u32_at(value, V_IP)),
            dst_port: u16::from_le_bytes([value[V_PORT], value[V_PORT + 1]]),
            queue: u32_at(value, V_QUEUE),
        },
        slot: u32_at(value, V_SLOT),
    })
}

fn ifname(ifindex: u32) -> String {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if p.is_null() {
        return format!("if{ifindex}");
    }
    unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn setup_err(path: &Path, what: &str, e: &dyn std::fmt::Display) -> XdpError {
    XdpError::Setup {
        interface: "-".into(),
        device: None,
        endpoint: None,
        reason: format!("ownership record {}: {what}: {e}", path.display()),
        remedy: "check that the bpf filesystem is mounted at /sys/fs/bpf and writable, and that \
                 the process has CAP_BPF; leftover directories under /sys/fs/bpf/xdp/gun-* of dead \
                 processes are cleaned up on the next start"
            .into(),
    }
}

fn open_dir(dir: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn try_flock_ex(fd: &OwnedFd) -> io::Result<bool> {
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(e)
    }
}

fn random_id() -> io::Result<String> {
    let uuid = fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let short: String = uuid
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(12)
        .collect();
    Ok(format!("{:x}-{nanos:x}-{short}", std::process::id()))
}

pub(crate) struct Owner {
    dir: PathBuf,
    _lock: OwnedFd,
    map: OwnedFd,
}

impl Owner {
    pub(crate) fn create(bpffs_xdp_dir: &Path, _lock: &BpffsLock) -> Result<Self, XdpError> {
        let mut dir = None;
        for _ in 0..CREATE_ATTEMPTS {
            let id = random_id().map_err(|e| setup_err(bpffs_xdp_dir, "cannot make an id", &e))?;
            let candidate = bpffs_xdp_dir.join(format!("{OWNER_PREFIX}{id}"));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    dir = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(setup_err(&candidate, "cannot create the directory", &e)),
            }
        }
        let dir = dir.ok_or_else(|| {
            setup_err(
                bpffs_xdp_dir,
                "cannot create",
                &"every random directory name was taken",
            )
        })?;
        Self::build(&dir).map_err(|e| {
            let mut failures = Vec::new();
            let pin = dir.join(MAP_PIN);
            for (what, operation, path, r) in [
                ("unpin the map", "unpin_map", &pin, fs::remove_file(&pin)),
                (
                    "remove the directory",
                    "remove_directory",
                    &dir,
                    fs::remove_dir(&dir),
                ),
            ] {
                match r {
                    Err(re) if re.kind() != io::ErrorKind::NotFound => {
                        tracing::warn!(
                            path = %path.display(),
                            operation,
                            error = %re,
                            "XDP context ownership record cleanup failed"
                        );
                        failures.push(format!("cannot {what}: {re}"));
                    }
                    _ => {}
                }
            }
            match e {
                XdpError::Setup {
                    interface,
                    device,
                    endpoint,
                    reason,
                    remedy,
                } if !failures.is_empty() => XdpError::Setup {
                    interface,
                    device,
                    endpoint,
                    reason: format!("{reason}; cleanup also failed: {}", failures.join("; ")),
                    remedy,
                },
                other => other,
            }
        })
    }

    fn build(dir: &Path) -> Result<Self, XdpError> {
        let lock = open_dir(dir).map_err(|e| setup_err(dir, "cannot open", &e))?;
        match try_flock_ex(&lock) {
            Ok(true) => {}
            Ok(false) => return Err(setup_err(dir, "cannot lock", &"already locked")),
            Err(e) => return Err(setup_err(dir, "cannot lock", &e)),
        }
        let map = bpf_sys::map_create(
            bpf_sys::BPF_MAP_TYPE_HASH,
            KEY_LEN as u32,
            VALUE_LEN as u32,
            MAP_CAPACITY,
            MAP_NAME,
        )
        .map_err(|e| setup_err(dir, "cannot create the map", &e))?;
        let pin = dir.join(MAP_PIN);
        bpf_sys::obj_pin(map.as_fd(), &pin)
            .map_err(|e| setup_err(&pin, "cannot pin the map", &e))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            map,
        })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn remove(self) -> Result<(), XdpError> {
        let pin = self.dir.join(MAP_PIN);
        match fs::remove_file(&pin) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(setup_err(&pin, "cannot unpin the map", &e)),
        }
        fs::remove_dir(&self.dir)
            .map_err(|e| setup_err(&self.dir, "cannot remove the directory", &e))
    }
}

impl RecordStore for Owner {
    fn put(&mut self, r: &InstalledRule) -> io::Result<()> {
        bpf_sys::map_update(
            self.map.as_fd(),
            &encode_key(r.ifindex, r.location),
            &encode_value(r),
        )
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::E2BIG) {
                io::Error::other(format!(
                    "the ownership record is full ({MAP_CAPACITY} entries)"
                ))
            } else {
                e
            }
        })
    }

    fn remove(&mut self, r: &InstalledRule) -> io::Result<()> {
        match bpf_sys::map_delete(self.map.as_fd(), &encode_key(r.ifindex, r.location)) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            other => other,
        }
    }

    fn all(&self) -> io::Result<Vec<InstalledRule>> {
        let mut out = Vec::new();
        let mut prev: Option<Vec<u8>> = None;
        while let Some(key) = bpf_sys::map_next_key(self.map.as_fd(), prev.as_deref(), KEY_LEN)? {
            let value =
                bpf_sys::map_lookup(self.map.as_fd(), &key, VALUE_LEN)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "record entry vanished while being read",
                    )
                })?;
            let e = decode(&key, &value)?;
            out.push(InstalledRule {
                device: ifname(e.ifindex),
                ifindex: e.ifindex,
                location: e.location,
                slot: e.slot,
                spec: e.spec,
            });
            prev = Some(key);
        }
        Ok(out)
    }
}

pub(crate) fn dead_owners(bpffs_xdp_dir: &Path, _lock: &BpffsLock) -> Result<Vec<Owner>, XdpError> {
    let entries = fs::read_dir(bpffs_xdp_dir)
        .map_err(|e| setup_err(bpffs_xdp_dir, "cannot list the owners", &e))?;
    let mut dead = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| setup_err(bpffs_xdp_dir, "cannot list the owners", &e))?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(OWNER_PREFIX)
        {
            continue;
        }
        let dir = entry.path();
        let lock = match open_dir(&dir) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(setup_err(&dir, "cannot open", &e)),
        };
        match try_flock_ex(&lock) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => return Err(setup_err(&dir, "cannot lock", &e)),
        }
        let pin = dir.join(MAP_PIN);
        match bpf_sys::obj_get(&pin) {
            Ok(map) => dead.push(Owner {
                dir,
                _lock: lock,
                map,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::remove_dir(&dir)
                    .map_err(|e| setup_err(&dir, "cannot remove the empty directory", &e))?;
            }
            Err(e) => return Err(setup_err(&pin, "cannot open the pinned map", &e)),
        }
    }
    Ok(dead)
}
