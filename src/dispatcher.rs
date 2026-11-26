#![allow(clippy::arithmetic_side_effects)]

use {
    crate::{
        bpf_sys,
        device::NetworkDevice,
        netlink::{
            self, XdpAttachment, netlink_attach_xdp, netlink_detach_xdp_expected, xdp_attachment,
        },
    },
    aya::{
        Ebpf, EbpfLoader,
        programs::{Extension, Xdp, extension::ExtensionLinkId, links::FdLink},
    },
    std::{
        error::Error,
        fs, io,
        os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
        path::{Path, PathBuf},
    },
};

pub(crate) const DROP_MULTI_FRAGS_GLOBAL: &str = "DROP_MULTI_FRAGS";

const DISPATCHER_MAGIC: u8 = 236;
const DISPATCHER_VERSION: u8 = 3;
const DISPATCHER_RETVAL: u32 = 31;
pub const MAX_DISPATCHER_SLOTS: usize = 10;

const XDP_PASS: u32 = 2;

pub const BPFFS_XDP_DIR: &str = "/sys/fs/bpf/xdp";

pub const OUR_MEMBER_NAME: &str = "allnodes_xdp_rx";
const _: () = assert!(OUR_MEMBER_NAME.len() < 16);

pub const LEGACY_MEMBER_NAME: &str = "agave_xdp_rx";

pub fn is_our_member(name: &str) -> bool {
    name == OUR_MEMBER_NAME || name == LEGACY_MEMBER_NAME
}

pub(crate) const XSKS_MAP: &str = "XSKS";
pub(crate) const OWNED_MAP: &str = "OWNED";

const PRESENCE_PREFIX: &str = "allnodes-";
const LEGACY_PRESENCE_PREFIX: &str = "agave-";


fn member_dir(if_index: u32, prog_id: u32) -> PathBuf {
    presence_dir(if_index).join(format!("m{prog_id}"))
}

fn existing_member_dir(if_index: u32, prog_id: u32) -> PathBuf {
    let ours = member_dir(if_index, prog_id);
    if ours.exists() {
        return ours;
    }
    let legacy = legacy_presence_dir(if_index).join(format!("m{prog_id}"));
    if legacy.exists() { legacy } else { ours }
}

fn object_hash() -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in crate::objects::CLASSIFIER.iter() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")
}

pub struct MemberMarker {
    _fd: OwnedFd,
    if_index: u32,
    prog_id: u32,
}

impl MemberMarker {
    pub fn claim(if_index: u32, prog_id: u32) -> Result<Self, Box<dyn Error>> {
        let dir = member_dir(if_index, prog_id);
        let build = dir.join(object_hash());
        fs::create_dir_all(&build).map_err(|err| bpffs_dir_error(&build.to_string_lossy(), err))?;
        Ok(Self {
            _fd: hold_shared(&dir)?,
            if_index,
            prog_id,
        })
    }
}

fn hold_shared(dir: &Path) -> Result<OwnedFd, Box<dyn Error>> {
    let fd = open_dir(dir)?;
    for _ in 0..100 {
        if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            return Ok(fd);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            return Err(format!("lock on {} failed: {err}", dir.display()).into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(format!(
        "lock on {} stayed held for a second; another process has it exclusively",
        dir.display()
    )
    .into())
}

fn marker_ids_any(if_index: u32) -> Vec<u32> {
    let mut ids = Vec::new();
    for dir in [presence_dir(if_index), legacy_presence_dir(if_index)] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        ids.extend(entries.flatten().filter_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .strip_prefix('m')
                .and_then(|id| id.parse::<u32>().ok())
        }));
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub fn any_member_live(if_index: u32) -> bool {
    marker_ids_any(if_index)
        .into_iter()
        .any(|id| member_is_live(if_index, id))
}

pub fn member_is_live(if_index: u32, prog_id: u32) -> bool {
    marker_state(&existing_member_dir(if_index, prog_id)) != MarkerState::Dead
}

pub fn member_build_matches(if_index: u32, prog_id: u32) -> bool {
    let wanted = object_hash();
    fs::read_dir(member_dir(if_index, prog_id))
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy() == wanted)
        })
        .unwrap_or(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerState {
    Missing,
    Live,
    Dead,
}

pub fn marker_state(dir: &Path) -> MarkerState {
    if !dir.is_dir() {
        return MarkerState::Missing;
    }
    let Ok(fd) = open_dir(dir) else {
        return MarkerState::Live;
    };
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return MarkerState::Live;
    }
    MarkerState::Dead
}

pub fn member_is_dead(if_index: u32, prog_id: u32) -> bool {
    marker_state(&existing_member_dir(if_index, prog_id)) == MarkerState::Dead
}

pub(crate) fn presence_dir(if_index: u32) -> PathBuf {
    Path::new(BPFFS_XDP_DIR).join(format!("{PRESENCE_PREFIX}{if_index}"))
}

pub(crate) fn legacy_presence_dir(if_index: u32) -> PathBuf {
    Path::new(BPFFS_XDP_DIR).join(format!("{LEGACY_PRESENCE_PREFIX}{if_index}"))
}

pub fn remove_interface_state(if_index: u32) -> Vec<String> {
    let pins = format!("dispatch-{if_index}-");
    let records = [presence_dir(if_index), legacy_presence_dir(if_index)];
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(BPFFS_XDP_DIR) else {
        return removed;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if (name.starts_with(&pins) || records.contains(&entry.path()))
            && fs::remove_dir_all(entry.path()).is_ok()
        {
            removed.push(name);
        }
    }
    removed
}

fn open_dir(dir: &Path) -> Result<OwnedFd, Box<dyn Error>> {
    let path = std::ffi::CString::new(dir.to_string_lossy().as_bytes())?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(format!("open {}: {}", dir.display(), std::io::Error::last_os_error()).into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpDispatcherConfig {
    magic: u8,
    dispatcher_version: u8,
    num_progs_enabled: u8,
    is_xdp_frags: u8,
    chain_call_actions: [u32; MAX_DISPATCHER_SLOTS],
    run_prios: [u32; MAX_DISPATCHER_SLOTS],
    program_flags: [u32; MAX_DISPATCHER_SLOTS],
    is_xdp_devbound: u8,
    _pad: [u8; 3],
}

unsafe impl aya::Pod for XdpDispatcherConfig {}

impl XdpDispatcherConfig {
    fn pass_through(num_progs: u8) -> Self {
        let mut chain_call_actions = [0u32; MAX_DISPATCHER_SLOTS];
        let mut run_prios = [0u32; MAX_DISPATCHER_SLOTS];
        for i in 0..num_progs as usize {
            chain_call_actions[i] = (1 << XDP_PASS) | (1 << DISPATCHER_RETVAL);
            run_prios[i] = 50;
        }
        Self {
            magic: DISPATCHER_MAGIC,
            dispatcher_version: DISPATCHER_VERSION,
            num_progs_enabled: num_progs,
            is_xdp_frags: 0,
            chain_call_actions,
            run_prios,
            program_flags: [0; MAX_DISPATCHER_SLOTS],
            is_xdp_devbound: 0,
            _pad: [0; 3],
        }
    }

    fn from_foreign(foreign: &[MemberEntry], with_ours: bool) -> Self {
        let mut chain_call_actions = [0u32; MAX_DISPATCHER_SLOTS];
        let mut run_prios = [0u32; MAX_DISPATCHER_SLOTS];
        let mut program_flags = [0u32; MAX_DISPATCHER_SLOTS];
        for (i, e) in foreign.iter().enumerate() {
            chain_call_actions[i] = e.action;
            run_prios[i] = e.prio;
            program_flags[i] = e.flags;
        }
        let ours = foreign.len();
        if with_ours {
            chain_call_actions[ours] = (1 << XDP_PASS) | (1 << DISPATCHER_RETVAL);
            run_prios[ours] = 50;
        }
        Self {
            magic: DISPATCHER_MAGIC,
            dispatcher_version: DISPATCHER_VERSION,
            num_progs_enabled: (ours + usize::from(with_ours)) as u8,
            is_xdp_frags: 0,
            chain_call_actions,
            run_prios,
            program_flags,
            is_xdp_devbound: 0,
            _pad: [0; 3],
        }
    }
}

#[derive(Clone, Copy)]
struct MemberEntry {
    action: u32,
    prio: u32,
    flags: u32,
}

const CFG_CHAIN_CALL_ACTIONS: usize = std::mem::offset_of!(XdpDispatcherConfig, chain_call_actions);
const CFG_RUN_PRIOS: usize = std::mem::offset_of!(XdpDispatcherConfig, run_prios);
const CFG_PROGRAM_FLAGS: usize = std::mem::offset_of!(XdpDispatcherConfig, program_flags);
const CFG_IS_XDP_DEVBOUND: usize = std::mem::offset_of!(XdpDispatcherConfig, is_xdp_devbound);
const CFG_V2_LEN: usize = CFG_IS_XDP_DEVBOUND;
const CFG_V3_LEN: usize = size_of::<XdpDispatcherConfig>();
const _: () = assert!(CFG_V3_LEN == 128);
const _: () = assert!(CFG_CHAIN_CALL_ACTIONS == 4);
const _: () = assert!(CFG_RUN_PRIOS == 44);
const _: () = assert!(CFG_PROGRAM_FLAGS == 84);
const _: () = assert!(CFG_IS_XDP_DEVBOUND == 124);

fn parse_incumbent_config(bytes: &[u8]) -> Result<Vec<MemberEntry>, String> {
    if bytes.len() < CFG_V2_LEN || bytes[0] != DISPATCHER_MAGIC {
        return Err("not a libxdp dispatcher config (bad magic/length)".into());
    }
    let version = bytes[1];
    if version != 2 && version != 3 {
        return Err(format!("unsupported dispatcher config version {version} (expected 2 or 3)"));
    }
    if bytes[3] != 0 {
        return Err("xdp-frags-aware dispatcher is not supported for joining".into());
    }
    if version == 3 && bytes.len() >= CFG_V3_LEN && bytes[CFG_IS_XDP_DEVBOUND] != 0 {
        return Err("device-bound dispatcher is not supported for joining".into());
    }
    let num = bytes[2] as usize;
    if num > MAX_DISPATCHER_SLOTS {
        return Err(format!("dispatcher reports {num} members (> {MAX_DISPATCHER_SLOTS})"));
    }
    let rd = |off: usize| u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
    Ok((0..num)
        .map(|i| MemberEntry {
            action: rd(CFG_CHAIN_CALL_ACTIONS + i * 4),
            prio: rd(CFG_RUN_PRIOS + i * 4),
            flags: rd(CFG_PROGRAM_FLAGS + i * 4),
        })
        .collect())
}

struct Member {
    ebpf: Ebpf,
    prog_name: String,
    link_id: Option<ExtensionLinkId>,
}

fn bpffs_dir_error(path: &str, err: std::io::Error) -> Box<dyn Error> {
    match err.kind() {
        std::io::ErrorKind::NotFound => format!(
            "XDP chain loading requires a bpf filesystem mounted at /sys/fs/bpf: that is \
             where the shared dispatcher is pinned, and it is how other XDP loaders find our \
             program. {path} cannot be created because /sys/fs/bpf is not a mounted bpf \
             filesystem. Mount it with `mount -t bpf bpf /sys/fs/bpf`; in a container, \
             bind-mount the host's and check with `mount | grep bpf` INSIDE the container that \
             it really arrived"
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "XDP chain loading requires write access to /sys/fs/bpf, where the shared \
             dispatcher is pinned. {path} cannot be created: the filesystem is mounted, but it \
             is mode 700 and owned by root by default. Create /sys/fs/bpf/xdp and give it to the \
             user the service runs as (`install -d -o <user> /sys/fs/bpf/xdp`)"
        ),
        _ => format!(
            "XDP chain loading requires {path} on the bpf filesystem, where the shared \
             dispatcher is pinned: {err}"
        ),
    }
    .into()
}

pub struct BpffsLock {
    fd: RawFd,
}

impl BpffsLock {
    pub fn prepare_dir() -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(BPFFS_XDP_DIR).map_err(|err| bpffs_dir_error(BPFFS_XDP_DIR, err))
    }

    pub fn acquire() -> Result<Self, Box<dyn Error>> {
        Self::prepare_dir()?;
        let fd = Self::open()?;
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("flock {BPFFS_XDP_DIR}: {err}").into());
        }
        Ok(Self { fd })
    }

    pub fn try_acquire() -> Result<Option<Self>, Box<dyn Error>> {
        let fd = Self::open()?;
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(format!("flock {BPFFS_XDP_DIR}: {err}").into());
        }
        Ok(Some(Self { fd }))
    }

    fn open() -> Result<RawFd, Box<dyn Error>> {
        let path = std::ffi::CString::new(BPFFS_XDP_DIR)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!("open {BPFFS_XDP_DIR}: {}", std::io::Error::last_os_error()).into());
        }
        Ok(fd)
    }
}

impl Drop for BpffsLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
            libc::close(self.fd);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainState {
    Present,
    Detached,
    NotADispatcher(u32),
    Missing(u32),
}

pub fn member_in_chain(
    if_index: u32,
    member_id: u32,
    _lock: Option<&BpffsLock>,
) -> Result<ChainState, Box<dyn Error>> {
    let Some(att) = xdp_attachment(if_index)? else {
        return Ok(ChainState::Detached);
    };
    let dir = pin_dir(if_index, att.prog_id);
    match fs::metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Ok(ChainState::NotADispatcher(att.prog_id)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(ChainState::NotADispatcher(att.prog_id));
        }
        Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display()).into()),
    }
    let present = read_members(&dir)?.iter().any(|(_, id)| *id == member_id);
    Ok(if present {
        ChainState::Present
    } else {
        ChainState::Missing(att.prog_id)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachMode {
    Native,
    Generic,
    NativeOrGeneric,
}

impl AttachMode {
    const fn accepts(self, drv: bool) -> bool {
        match self {
            AttachMode::Native => drv,
            AttachMode::Generic => !drv,
            AttachMode::NativeOrGeneric => true,
        }
    }
}

const fn mode_name(drv: bool) -> &'static str {
    if drv { "driver (drv)" } else { "generic (skb)" }
}

pub struct Dispatcher {
    ebpf: Ebpf,
    members: Vec<Member>,
    slots: u8,
    our_slot: usize,
    prog_id: Option<u32>,
    if_index: Option<u32>,
    drv: bool,
    has_foreign: bool,
    pin_dir: Option<PathBuf>,
    marker: Option<MemberMarker>,
}

impl Dispatcher {
    pub fn load(num_progs: u8) -> Result<Self, Box<dyn Error>> {
        Self::load_with_config(XdpDispatcherConfig::pass_through(num_progs))
    }

    fn load_with_config(config: XdpDispatcherConfig) -> Result<Self, Box<dyn Error>> {
        let num_progs = config.num_progs_enabled;
        if num_progs as usize > MAX_DISPATCHER_SLOTS {
            return Err(format!("dispatcher supports at most {MAX_DISPATCHER_SLOTS} programs").into());
        }
        let mut ebpf = EbpfLoader::new()
            .override_global("conf", &config, true)
            .load(crate::objects::DISPATCHER)?;
        let p: &mut Xdp = ebpf
            .program_mut("xdp_dispatcher")
            .ok_or("xdp_dispatcher program not found")?
            .try_into()?;
        p.load()?;
        let prog_id = {
            let p: &Xdp = ebpf
                .program("xdp_dispatcher")
                .ok_or("dispatcher not loaded")?
                .try_into()?;
            p.info()?.id()
        };
        Ok(Self {
            ebpf,
            members: Vec::new(),
            slots: num_progs,
            our_slot: 0,
            prog_id: Some(prog_id),
            if_index: None,
            drv: true,
            has_foreign: false,
            pin_dir: None,
            marker: None,
        })
    }

    fn build_and_attach_fresh(
        dev: &NetworkDevice,
        mode: AttachMode,
        replace: Option<XdpAttachment>,
        lock: &BpffsLock,
    ) -> Result<Self, Box<dyn Error>> {
        let drop_frags = is_i40e(dev)?;
        let mut me = Self::load(1)?;
        let (member, link_id) = me.load_freplace_member(
            crate::objects::CLASSIFIER,
            OUR_MEMBER_NAME,
            "prog0",
            drop_frags,
        )?;
        me.members.push(Member {
            ebpf: member,
            prog_name: OUR_MEMBER_NAME.to_string(),
            link_id: Some(link_id),
        });
        me.record_member(dev.if_index())?;
        if let Err(e) = me.pin_and_attach(dev, mode, replace, &[], &[], lock) {
            return Err(me.release_marker_after(e));
        }
        Ok(me)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_and_attach_joined(
        dev: &NetworkDevice,
        mode: AttachMode,
        att: XdpAttachment,
        incumbent_dir: &Path,
        foreign_slots: &[usize],
        with_ours: bool,
        lock: &BpffsLock,
    ) -> Result<Self, Box<dyn Error>> {
        let cfg_bytes = read_dispatcher_config(att.prog_id)?;
        let entries = parse_incumbent_config(&cfg_bytes).map_err(|e| {
            format!(
                "XDP chain loading can only join a dispatcher it understands, and the one on \
                 {name} cannot be read: {e}. Detach it with `ip link set dev {name} xdp off` if \
                 nothing else needs it, or turn XDP off for this service",
                name = dev.name()
            )
        })?;
        let foreign_entries: Vec<MemberEntry> = foreign_slots
            .iter()
            .map(|&s| {
                entries
                    .get(s)
                    .copied()
                    .ok_or_else(|| format!("peer dispatcher member slot {s} missing from its config"))
            })
            .collect::<Result<_, _>>()?;
        let num_foreign = foreign_entries.len();
        if num_foreign + usize::from(with_ours) > MAX_DISPATCHER_SLOTS {
            return Err(format!(
                "XDP chain loading requires a free slot in the XDP dispatcher on {name}, and \
                 that dispatcher is full: its {num_foreign} members occupy all \
                 {MAX_DISPATCHER_SLOTS} slots libxdp allows. Detach one of them with \
                 `xdp-loader unload {name} --id <ID>`, listing them with `xdp-loader status`",
                name = dev.name()
            )
            .into());
        }

        let foreign: Vec<OwnedFd> = foreign_slots
            .iter()
            .map(|&s| bpf_sys::obj_get(&incumbent_dir.join(format!("prog{s}-prog"))))
            .collect::<Result<Vec<_>, _>>()?;

        let config = XdpDispatcherConfig::from_foreign(&foreign_entries, with_ours);
        let mut me = Self::load_with_config(config)?;
        me.our_slot = num_foreign;
        me.has_foreign = true;
        let disp_fd = {
            let p: &Xdp = me
                .ebpf
                .program("xdp_dispatcher")
                .ok_or("dispatcher not loaded")?
                .try_into()?;
            p.fd()?.try_clone()?
        };

        let btf = bpf_sys::btf_bytes_by_id(bpf_sys::prog_info(disp_fd.as_fd())?.btf_id)?;
        let mut foreign_links = Vec::with_capacity(num_foreign);
        for (k, ffd) in foreign.iter().enumerate() {
            let target = bpf_sys::btf_func_id(&btf, &format!("prog{k}"))
                .ok_or_else(|| format!("prog{k} not found in dispatcher BTF"))?;
            foreign_links.push(bpf_sys::link_create_freplace(
                ffd.as_fd(),
                disp_fd.as_fd(),
                target,
            )?);
        }

        if with_ours {
            let (member, link_id) = me.load_freplace_member(
                crate::objects::CLASSIFIER,
                OUR_MEMBER_NAME,
                &format!("prog{num_foreign}"),
                is_i40e(dev)?,
            )?;
            me.members.push(Member {
                ebpf: member,
                prog_name: OUR_MEMBER_NAME.to_string(),
                link_id: Some(link_id),
            });
            me.record_member(dev.if_index())?;
        }

        if let Err(e) = me.pin_and_attach(dev, mode, Some(att), &foreign, &foreign_links, lock) {
            return Err(me.release_marker_after(e));
        }
        Ok(me)
    }

    fn load_freplace_member(
        &self,
        object: &[u8],
        prog_name: &str,
        target_func: &str,
        drop_multi_frags: bool,
    ) -> Result<(Ebpf, ExtensionLinkId), Box<dyn Error>> {
        let mut loader = EbpfLoader::new();
        loader.extension(prog_name);
        if drop_multi_frags {
            loader.override_global(DROP_MULTI_FRAGS_GLOBAL, &1u8, true);
        }
        let mut member = loader.load(object)?;
        let dispatcher: &Xdp = self
            .ebpf
            .program("xdp_dispatcher")
            .ok_or("dispatcher not loaded")?
            .try_into()?;
        let dispatcher_fd = dispatcher.fd()?.try_clone()?;
        let ext: &mut Extension = member
            .program_mut(prog_name)
            .ok_or_else(|| format!("{prog_name} not found in member object"))?
            .try_into()?;
        ext.load(dispatcher_fd, target_func)?;
        let link_id = ext.attach()?;
        Ok((member, link_id))
    }

    pub fn attach_member(
        &mut self,
        object: &[u8],
        prog_name: &str,
    ) -> Result<&mut Ebpf, Box<dyn Error>> {
        let slot = self.members.len();
        if slot >= self.slots as usize {
            return Err(format!("all {} dispatcher slots are configured", self.slots).into());
        }
        let (member, link_id) =
            self.load_freplace_member(object, prog_name, &format!("prog{slot}"), false)?;
        self.members.push(Member {
            ebpf: member,
            prog_name: prog_name.to_string(),
            link_id: Some(link_id),
        });
        Ok(&mut self.members.last_mut().expect("just pushed").ebpf)
    }

    pub fn attach(&mut self, dev: &NetworkDevice, mode: AttachMode) -> Result<(), Box<dyn Error>> {
        self.attach_and_replace(dev, mode, None)
    }

    fn attach_and_replace(
        &mut self,
        dev: &NetworkDevice,
        mode: AttachMode,
        replace: Option<XdpAttachment>,
    ) -> Result<(), Box<dyn Error>> {
        let prog_fd = {
            let p: &Xdp = self
                .ebpf
                .program("xdp_dispatcher")
                .ok_or("dispatcher not loaded")?
                .try_into()?;
            p.fd()?.as_fd().as_raw_fd()
        };
        let ifindex = dev.if_index();
        match replace {
            Some(att) => {
                if !mode.accepts(att.drv) {
                    return Err(format!(
                        "the XDP dispatcher already on {name} is attached in {have} mode and this \
                         process is configured for {want}; one interface carries one mode, and \
                         a mode cannot be changed in place. Configure {have} mode to join it, or \
                         detach it with `ip link set dev {name} xdp off` if nothing else uses it",
                        name = dev.name(),
                        have = mode_name(att.drv),
                        want = mode_name(!att.drv),
                    )
                    .into());
                }
                let expected = bpf_sys::prog_fd_by_id(att.prog_id)?;
                netlink_attach_xdp(ifindex, prog_fd, att.drv, Some(expected.as_raw_fd())).map_err(
                    |e| format!("replacing the XDP dispatcher on {} failed: {e}", dev.name()),
                )?;
                self.drv = att.drv;
            }
            None => {
                let first = !matches!(mode, AttachMode::Generic);
                match netlink_attach_xdp(ifindex, prog_fd, first, None) {
                    Ok(()) => self.drv = first,
                    Err(e) if mode == AttachMode::NativeOrGeneric => {
                        tracing::debug!(
                            "xdp dispatcher: native attach to {} failed ({e}); using skb mode",
                            dev.name()
                        );
                        netlink_attach_xdp(ifindex, prog_fd, false, None).map_err(|e| {
                            format!(
                                "attaching the XDP dispatcher to {} in {} mode failed: {e}",
                                dev.name(),
                                mode_name(false)
                            )
                        })?;
                        self.drv = false;
                    }
                    Err(e) => {
                        return Err(format!(
                            "attaching the XDP dispatcher to {} in {} mode failed: {e}",
                            dev.name(),
                            mode_name(first)
                        )
                        .into());
                    }
                }
            }
        }
        self.if_index = Some(ifindex);
        Ok(())
    }

    fn pin_and_attach(
        &mut self,
        dev: &NetworkDevice,
        mode: AttachMode,
        replace: Option<XdpAttachment>,
        foreign: &[OwnedFd],
        foreign_links: &[OwnedFd],
        lock: &BpffsLock,
    ) -> Result<(), Box<dyn Error>> {
        let pinned = self.pin_members(dev.if_index(), foreign, foreign_links, lock);
        let result = pinned.and_then(|()| self.attach_and_replace(dev, mode, replace));
        if let Err(e) = result {
            return Err(match self.cleanup_pin_dir() {
                Ok(()) => e,
                Err(ce) => format!("{e}; removing its pin directory also failed: {ce}").into(),
            });
        }
        Ok(())
    }

    fn our_member_id(&self) -> Result<u32, Box<dyn Error>> {
        let member = self
            .members
            .first()
            .ok_or("dispatcher has no member of ours")?;
        let program: &Extension = member
            .ebpf
            .program(&member.prog_name)
            .ok_or("our member program is not in its object")?
            .try_into()?;
        Ok(bpf_sys::prog_info(program.fd()?.as_fd())?.id)
    }

    fn record_member(&mut self, if_index: u32) -> Result<(), Box<dyn Error>> {
        let prog_id = self.our_member_id()?;
        self.marker = Some(MemberMarker::claim(if_index, prog_id)?);
        let dir = member_dir(if_index, prog_id);
        for name in [XSKS_MAP, OWNED_MAP] {
            let path = dir.join(name.to_lowercase());
            if path.exists() {
                continue;
            }
            let map = self
                .our_member_mut()?
                .map(name)
                .ok_or_else(|| format!("{name} map not found in our member"))?;
            if let Err(e) = map.pin(&path) {
                return Err(self.release_marker_after(Box::new(e)));
            }
        }
        Ok(())
    }

    fn release_marker_after(&mut self, e: Box<dyn Error>) -> Box<dyn Error> {
        let Some(marker) = self.marker.take() else {
            return e;
        };
        let (if_index, id) = (marker.if_index, marker.prog_id);
        drop(marker);
        match remove_marker_dir(if_index, id) {
            Ok(()) => e,
            Err(me) => format!("{e}; removing its presence marker also failed: {me}").into(),
        }
    }

    pub fn abandon_presence(&mut self) {
        self.marker = None;
    }

    fn cleanup_pin_dir(&mut self) -> io::Result<()> {
        match self.pin_dir.take() {
            Some(dir) => match fs::remove_dir_all(&dir) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
            None => Ok(()),
        }
    }

    pub fn pin(&mut self, if_index: u32, lock: &BpffsLock) -> Result<(), Box<dyn Error>> {
        self.pin_members(if_index, &[], &[], lock)
    }

    fn pin_members(
        &mut self,
        if_index: u32,
        foreign: &[OwnedFd],
        foreign_links: &[OwnedFd],
        _lock: &BpffsLock,
    ) -> Result<(), Box<dyn Error>> {
        let prog_id = self.prog_id.ok_or("dispatcher not loaded")?;
        let dir = pin_dir(if_index, prog_id);
        fs::create_dir_all(&dir).map_err(|err| bpffs_dir_error(&dir.to_string_lossy(), err))?;
        self.pin_dir = Some(dir.clone());
        for (i, (prog, link)) in foreign.iter().zip(foreign_links).enumerate() {
            bpf_sys::obj_pin(prog.as_fd(), &dir.join(format!("prog{i}-prog")))?;
            bpf_sys::obj_pin(link.as_fd(), &dir.join(format!("prog{i}-link")))?;
        }
        let base = self.our_slot;
        for (j, member) in self.members.iter_mut().enumerate() {
            let slot = base + j;
            let ext: &mut Extension = member
                .ebpf
                .program_mut(&member.prog_name)
                .ok_or("member program missing at pin")?
                .try_into()?;
            ext.pin(dir.join(format!("prog{slot}-prog")))?;
            let link_id = member
                .link_id
                .take()
                .ok_or("member freplace link already taken")?;
            let fd_link: FdLink = ext.take_link(link_id)?.into();
            fd_link.pin(dir.join(format!("prog{slot}-link")))?;
        }
        Ok(())
    }

    pub fn our_member_mut(&mut self) -> Result<&mut Ebpf, Box<dyn Error>> {
        Ok(&mut self
            .members
            .get_mut(0)
            .ok_or("dispatcher has no member of ours")?
            .ebpf)
    }

    pub fn member_id(&self) -> Result<u32, Box<dyn Error>> {
        self.our_member_id()
    }

    pub const fn is_native(&self) -> bool {
        self.drv
    }

    pub fn leave(mut self, dev: &NetworkDevice, lock: &BpffsLock) -> Result<(), Box<dyn Error>> {
        self.leave_in_place(dev, lock)
    }

    pub(crate) fn leave_in_place(
        &mut self,
        dev: &NetworkDevice,
        lock: &BpffsLock,
    ) -> Result<(), Box<dyn Error>> {
        if self.if_index.take().is_none() {
            return Ok(());
        }
        let pin_dir = self.pin_dir.take();
        let ours = self.prog_id;
        let id = self.our_member_id()?;
        let rebuilt = rebuild_without(dev, &|_, member| member == id, lock, &mut || {})
            .map(drop)
            .map_err(|e| format!("leaving the XDP chain on {}: {e}", dev.name()).into());
        let out_of_chain = rebuilt.is_ok();
        let marker = &mut self.marker;
        let left = finish_leave(
            rebuilt,
            || *marker = None,
            || remove_marker_dir(dev.if_index(), id),
        );
        if out_of_chain
            && let Some(dir) = pin_dir.as_deref()
            && let Err(e) = remove_orphaned_pins(dev.if_index(), ours, dir)
        {
            tracing::warn!(
                device = %dev.name(),
                path = %dir.display(),
                operation = "remove_detached_pins",
                error = %e,
                leftover = "pins of the detached XDP dispatcher",
                action = "remove at the next start",
                "XDP classifier dispatcher pins left behind"
            );
        }
        left
    }

    pub fn abandon(mut self) {
        self.if_index = None;
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        if let Some(if_index) = self.if_index
            && self.marker.is_some()
        {
            tracing::warn!(
                ifindex = if_index,
                state = "dead",
                reason = "dropped without leaving the chain",
                action = "remove at the next start",
                "XDP classifier member left behind"
            );
        }
    }
}

fn pins_orphaned(attached: Option<u32>, ours: Option<u32>) -> bool {
    ours.is_some() && attached != ours
}

fn remove_orphaned_pins(if_index: u32, ours: Option<u32>, dir: &Path) -> io::Result<()> {
    if !pins_orphaned(xdp_attachment(if_index)?.map(|a| a.prog_id), ours) {
        return Ok(());
    }
    match fs::remove_dir_all(dir) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn finish_leave(
    rebuilt: Result<(), Box<dyn Error>>,
    release_flock: impl FnOnce(),
    remove_marker: impl FnOnce() -> io::Result<()>,
) -> Result<(), Box<dyn Error>> {
    release_flock();
    match rebuilt {
        Ok(()) => remove_marker().map_err(|e| format!("removing our presence marker: {e}").into()),
        Err(e) => Err(format!(
            "{e}; the member stays with its marker and is removed at the next start"
        )
        .into()),
    }
}

type Removal = (Vec<u32>, Option<(u32, bool)>);

fn rebuild_without(
    dev: &NetworkDevice,
    drop_member: &dyn Fn(&str, u32) -> bool,
    lock: &BpffsLock,
    after_change: &mut dyn FnMut(),
) -> Result<Removal, Box<dyn Error>> {
    let if_index = dev.if_index();
    let Some(att) = xdp_attachment(if_index)? else {
        return Ok((Vec::new(), None));
    };
    let dir = pin_dir(if_index, att.prog_id);
    if !dir.is_dir() {
        return Ok((Vec::new(), None));
    }
    let members = read_members(&dir)?;
    let (dropped, kept): (Vec<_>, Vec<_>) = members
        .iter()
        .enumerate()
        .partition(|(_, (name, id))| drop_member(name, *id));
    if dropped.is_empty() {
        return Ok((Vec::new(), None));
    }
    let detached = kept.is_empty().then_some((att.prog_id, att.drv));
    if kept.is_empty() {
        let expected = bpf_sys::prog_fd_by_id(att.prog_id)?;
        netlink_detach_xdp_expected(if_index, att.drv, expected.as_raw_fd()).map_err(|e| {
            format!(
                "detaching the XDP dispatcher (id {}) from {} failed: {e}",
                att.prog_id,
                dev.name()
            )
        })?;
        fs::remove_dir_all(&dir).map_err(|e| format!("removing {}: {e}", dir.display()))?;
    } else {
        let slots: Vec<usize> = kept.iter().map(|(slot, _)| *slot).collect();
        let mode = if att.drv {
            AttachMode::Native
        } else {
            AttachMode::Generic
        };
        let rebuilt = Dispatcher::build_and_attach_joined(dev, mode, att, &dir, &slots, false, lock)?;
        if let Some(prog_id) = rebuilt.prog_id {
            sweep_orphan_dirs(if_index, prog_id, lock)
                .map_err(|e| format!("removing the replaced dispatcher's pins: {e}"))?;
        }
    }
    after_change();
    let mut removed = Vec::with_capacity(dropped.len());
    for (_, (_, id)) in dropped {
        remove_marker_dir(if_index, *id)?;
        removed.push(*id);
    }
    Ok((removed, detached))
}

fn remove_marker_dir(if_index: u32, prog_id: u32) -> io::Result<()> {
    for dir in [presence_dir(if_index), legacy_presence_dir(if_index)] {
        match fs::remove_dir_all(dir.join(format!("m{prog_id}"))) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

pub fn presence_ifindex(name: &str) -> Option<u32> {
    name.strip_prefix(PRESENCE_PREFIX)
        .or_else(|| name.strip_prefix(LEGACY_PRESENCE_PREFIX))?
        .parse()
        .ok()
}

pub fn reap_dead_members_everywhere(
    lock: &BpffsLock,
    configured: &[u32],
    after_change: &mut dyn FnMut(),
) -> Result<(Vec<ReapedOn>, Vec<ReapWarning>), Box<dyn Error>> {
    let entries = match fs::read_dir(BPFFS_XDP_DIR) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(format!("listing {BPFFS_XDP_DIR}: {e}").into()),
    };
    let mut ids = Vec::new();
    for entry in entries {
        if let Some(if_index) = presence_ifindex(&entry?.file_name().to_string_lossy()) {
            ids.push(if_index);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    let name = |if_index: u32| {
        NetworkDevice::new_from_index(if_index)
            .ok()
            .map(|dev| dev.name().to_string())
    };
    let mut pace = crate::pace::Pace::auto();
    reap_each(
        &ids,
        configured,
        |i| reap_dead_members_on(i, lock, after_change, &mut pace),
        name,
    )
}

fn pin_dir_ids(name: &str) -> Option<(u32, u32)> {
    let (if_index, prog_id) = name.strip_prefix("dispatch-")?.split_once('-')?;
    Some((if_index.parse().ok()?, prog_id.parse().ok()?))
}

pub type UnmarkedOn = (u32, Vec<u32>);

pub fn unmarked_members(_lock: &BpffsLock) -> Result<Vec<UnmarkedOn>, Box<dyn Error>> {
    let entries = match fs::read_dir(BPFFS_XDP_DIR) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("listing {BPFFS_XDP_DIR}: {e}").into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let Some((if_index, prog_id)) = pin_dir_ids(&entry?.file_name().to_string_lossy()) else {
            continue;
        };
        if xdp_attachment(if_index)?.map(|a| a.prog_id) != Some(prog_id) {
            continue;
        }
        let ids: Vec<u32> = read_members(&pin_dir(if_index, prog_id))?
            .into_iter()
            .filter(|(name, id)| {
                is_our_member(name)
                    && marker_state(&existing_member_dir(if_index, *id)) == MarkerState::Missing
            })
            .map(|(_, id)| id)
            .collect();
        if !ids.is_empty() {
            out.push((if_index, ids));
        }
    }
    Ok(out)
}

pub type UnattributedOn = (u32, u32, bool);

pub fn unattributed_programs() -> Result<Vec<UnattributedOn>, Box<dyn Error>> {
    let mut out = Vec::new();
    for (if_index, att) in netlink::xdp_attachments()? {
        let dir = pin_dir(if_index, att.prog_id);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => out.push((if_index, att.prog_id, att.drv)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                out.push((if_index, att.prog_id, att.drv))
            }
            Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display()).into()),
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReapedOn {
    pub ifindex: u32,
    pub members: Vec<u32>,
    pub markers: Vec<u32>,
    pub detached: Option<(u32, bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReapWarning {
    pub ifindex: u32,
    pub device: Option<String>,
    pub error: String,
}

fn reap_each<T>(
    ids: &[u32],
    configured: &[u32],
    mut reap: impl FnMut(u32) -> Result<Option<T>, Box<dyn Error>>,
    name: impl Fn(u32) -> Option<String>,
) -> Result<(Vec<T>, Vec<ReapWarning>), Box<dyn Error>> {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for &if_index in ids {
        match reap(if_index) {
            Ok(done) => out.extend(done),
            Err(e) if configured.contains(&if_index) => {
                let which = match name(if_index) {
                    Some(n) => format!("interface {n} (index {if_index})"),
                    None => format!("interface index {if_index}"),
                };
                return Err(format!("{which}: {e}").into());
            }
            Err(e) => warnings.push(ReapWarning {
                ifindex: if_index,
                device: name(if_index),
                error: e.to_string(),
            }),
        }
    }
    Ok((out, warnings))
}

fn reap_dead_members_on(
    if_index: u32,
    lock: &BpffsLock,
    after_change: &mut dyn FnMut(),
    pace: &mut crate::pace::Pace,
) -> Result<Option<ReapedOn>, Box<dyn Error>> {
    let dead: Vec<u32> = marker_ids_any(if_index)
        .into_iter()
        .filter(|id| member_is_dead(if_index, *id))
        .collect();
    if dead.is_empty() {
        return Ok(None);
    }
    let dev = match NetworkDevice::new_from_index(if_index) {
        Ok(dev) => dev,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) => {
            for id in &dead {
                remove_marker_dir(if_index, *id)?;
            }
            return Ok(Some(ReapedOn {
                ifindex: if_index,
                markers: dead,
                ..ReapedOn::default()
            }));
        }
        Err(e) => return Err(e.into()),
    };
    let paced = xdp_attachment(if_index)?.is_some_and(|a| a.drv);
    if paced {
        pace.before(dev.name(), "detach");
    }
    let (members, detached) = rebuild_without(
        &dev,
        &|name, id| is_our_member(name) && member_is_dead(if_index, id),
        lock,
        after_change,
    )?;
    if paced {
        pace.after(dev.name());
    }
    sweep_member_markers(if_index, &current_member_ids(if_index)?, lock)?;
    let markers = dead
        .into_iter()
        .filter(|id| !members.contains(id) && !existing_member_dir(if_index, *id).exists())
        .collect();
    Ok(Some(ReapedOn {
        ifindex: if_index,
        members,
        markers,
        detached,
    }))
}

pub fn owned_by_live_member(
    dev: &NetworkDevice,
    keys: &[u64],
    _lock: &BpffsLock,
) -> Result<Option<(u32, u64)>, Box<dyn Error>> {
    let if_index = dev.if_index();
    let Some(att) = xdp_attachment(if_index)? else {
        return Ok(None);
    };
    let dir = pin_dir(if_index, att.prog_id);
    if !dir.is_dir() {
        return Ok(None);
    }
    for (slot, (name, id)) in read_members(&dir)?.into_iter().enumerate() {
        if name != OUR_MEMBER_NAME || !member_is_live(if_index, id) {
            continue;
        }
        let prog = bpf_sys::obj_get(&dir.join(format!("prog{slot}-prog")))?;
        for map_id in bpf_sys::prog_info(prog.as_fd())?.map_ids {
            let map = bpf_sys::map_fd_by_id(map_id)?;
            if bpf_sys::map_info(map.as_fd())?.name != OWNED_MAP {
                continue;
            }
            for key in keys {
                if bpf_sys::map_lookup(map.as_fd(), &key.to_ne_bytes(), 4)?.is_some() {
                    return Ok(Some((id, *key)));
                }
            }
        }
    }
    Ok(None)
}

fn is_i40e(dev: &NetworkDevice) -> Result<bool, Box<dyn Error>> {
    match fs::symlink_metadata(format!("/sys/class/net/{}/device", dev.name())) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot inspect the device of {}: {e}", dev.name()).into()),
        Ok(_) => Ok(dev
            .driver()
            .map_err(|e| format!("cannot read the driver of {}: {e}", dev.name()))?
            == "i40e"),
    }
}

fn sweep_orphan_dirs(if_index: u32, keep_prog_id: u32, _lock: &BpffsLock) -> io::Result<()> {
    if xdp_attachment(if_index)?.map(|a| a.prog_id) != Some(keep_prog_id) {
        return Ok(());
    }
    let prefix = format!("dispatch-{if_index}-");
    let keep = format!("dispatch-{if_index}-{keep_prog_id}");
    for entry in fs::read_dir(BPFFS_XDP_DIR)? {
        let entry = entry?;
        match entry.file_name().to_str() {
            Some(name) if name.starts_with(&prefix) && name != keep => {
                fs::remove_dir_all(entry.path())?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn pin_dir(if_index: u32, prog_id: u32) -> PathBuf {
    Path::new(BPFFS_XDP_DIR).join(format!("dispatch-{if_index}-{prog_id}"))
}

pub enum Incumbent {
    Free,
    OurLeftover(XdpAttachment),
    LiveSibling(XdpAttachment),
    ForeignDispatcher(XdpAttachment),
    Opaque(u32),
    Unreadable(u32),
}

pub fn classify(dev: &NetworkDevice) -> Result<Incumbent, Box<dyn Error>> {
    let if_index = dev.if_index();
    let Some(attachment) = xdp_attachment(if_index)? else {
        return Ok(Incumbent::Free);
    };
    let dir = pin_dir(if_index, attachment.prog_id);
    match fs::metadata(&dir) {
        Ok(meta) if meta.is_dir() => {}
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(Incumbent::Unreadable(attachment.prog_id));
        }
        _ => return Ok(Incumbent::Opaque(attachment.prog_id)),
    }
    let members = read_members(&dir).unwrap_or_default();
    let ours = !members.is_empty() && members.iter().all(|(name, _)| is_our_member(name));
    let live = members
        .iter()
        .any(|(_, prog_id)| member_is_live(if_index, *prog_id));
    Ok(match (ours, live) {
        (true, false) => Incumbent::OurLeftover(attachment),
        (true, true) => Incumbent::LiveSibling(attachment),
        (false, _) => Incumbent::ForeignDispatcher(attachment),
    })
}

pub const CHANGED_UNDER_US: &str = "changed while it was being cleaned up";

pub fn remove_leftover(
    dev: &NetworkDevice,
    attachment: &XdpAttachment,
    _lock: &BpffsLock,
) -> Result<(), Box<dyn Error>> {
    let if_index = dev.if_index();
    match classify(dev)? {
        Incumbent::OurLeftover(current) if current.prog_id == attachment.prog_id => {}
        _ => {
            return Err(format!("the XDP program on {} {CHANGED_UNDER_US}", dev.name()).into());
        }
    }
    let members = read_members(&pin_dir(if_index, attachment.prog_id)).unwrap_or_default();
    let expected = bpf_sys::prog_fd_by_id(attachment.prog_id)?;
    netlink_detach_xdp_expected(if_index, attachment.drv, expected.as_raw_fd())?;
    let _ = fs::remove_dir_all(pin_dir(if_index, attachment.prog_id));
    for (_, id) in members {
        remove_marker_dir(if_index, id)?;
    }
    Ok(())
}

pub struct AdoptedMember {
    pub xsks: OwnedFd,
    pub owned: OwnedFd,
    #[allow(dead_code)]
    marker: MemberMarker,
    pub prog_id: u32,
}

pub fn adoptable(dev: &NetworkDevice) -> Option<AdoptedMember> {
    let (prog_id, xsks, owned) = inspect_adoptable(dev)?;
    let marker = MemberMarker::claim(dev.if_index(), prog_id).ok()?;
    Some(AdoptedMember {
        xsks,
        owned,
        marker,
        prog_id,
    })
}

pub fn can_adopt(dev: &NetworkDevice) -> bool {
    inspect_adoptable(dev).is_some()
}

fn inspect_adoptable(dev: &NetworkDevice) -> Option<(u32, OwnedFd, OwnedFd)> {
    let if_index = dev.if_index();
    let attachment = xdp_attachment(if_index).ok().flatten()?;
    let dir = pin_dir(if_index, attachment.prog_id);
    let members = read_members(&dir).ok()?;
    let (slot, (_, prog_id)) = members.into_iter().enumerate().find(|(_, (name, id))| {
        name.as_str() == OUR_MEMBER_NAME
            && member_is_dead(if_index, *id)
            && member_build_matches(if_index, *id)
    })?;

    let member = member_dir(if_index, prog_id);
    let xsks = bpf_sys::obj_get(&member.join(XSKS_MAP.to_lowercase())).ok()?;
    let owned = bpf_sys::obj_get(&member.join(OWNED_MAP.to_lowercase())).ok()?;

    let member_prog = bpf_sys::obj_get(&dir.join(format!("prog{slot}-prog"))).ok()?;
    let used = bpf_sys::prog_info(member_prog.as_fd()).ok()?.map_ids;
    for map in [&xsks, &owned] {
        let id = bpf_sys::map_info(map.as_fd()).ok()?.id;
        if !used.contains(&id) {
            tracing::debug!(
                "xdp: the pinned maps under m{prog_id} are not the ones its program uses; not \
                 adopting"
            );
            return None;
        }
    }
    Some((prog_id, xsks, owned))
}

pub fn attach_or_join(
    dev: &NetworkDevice,
    mode: AttachMode,
    lock: &BpffsLock,
) -> Result<Dispatcher, Box<dyn Error>> {
    let ifindex = dev.if_index();
    let dispatcher = match xdp_attachment(ifindex)? {
        None => Dispatcher::build_and_attach_fresh(dev, mode, None, lock)?,
        Some(att) => {
            let dir = pin_dir(ifindex, att.prog_id);
            if !dir.is_dir() {
                return Err(format!(
                    "XDP chain loading requires the incumbent program to be a libxdp \
                     dispatcher, and {name} has a non-dispatcher XDP program on its hook (id \
                     {id}) — there is nothing to chain onto. Load that program through libxdp \
                     (`xdp-loader load`) so both can share the hook, or detach it with `ip link \
                     set dev {name} xdp off` if nothing needs it",
                    name = dev.name(),
                    id = att.prog_id,
                )
                .into());
            }
            let members = read_members(&dir)?;
            let foreign_slots: Vec<usize> = members
                .iter()
                .enumerate()
                .filter(|(_, (name, id))| !is_our_member(name) || !member_is_dead(ifindex, *id))
                .map(|(slot, _)| slot)
                .collect();
            if !foreign_slots.is_empty() {
                tracing::debug!(
                    device = %dev.name(),
                    kept_count = foreign_slots.len(),
                    member_count = members.len(),
                    action = "rebuild the chain",
                    "XDP classifier chain keeps other members"
                );
            }
            if members.is_empty() && any_member_live(ifindex) {
                return Err(format!(
                    "{} carries an XDP dispatcher that is in use, but its pin directory is \
                     empty, so its members cannot be identified; refusing to rebuild it. Stop \
                     the other user of this interface, or detach the program with `ip link set \
                     dev {} xdp off`",
                    dev.name(),
                    dev.name()
                )
                .into());
            }
            if foreign_slots.is_empty() {
                tracing::debug!(
                    device = %dev.name(),
                    reason = "own stale dispatcher",
                    action = "replace",
                    "XDP classifier dispatcher replaced"
                );
                Dispatcher::build_and_attach_fresh(dev, mode, Some(att), lock)?
            } else {
                Dispatcher::build_and_attach_joined(
                    dev,
                    mode,
                    att,
                    &dir,
                    &foreign_slots,
                    true,
                    lock,
                )?
            }
        }
    };
    let mut warnings = Vec::new();
    if let Some(prog_id) = dispatcher.prog_id
        && let Err(e) = sweep_orphan_dirs(ifindex, prog_id, lock)
    {
        warnings.push(("remove_replaced_pins", e.to_string()));
    }
    match current_member_ids(ifindex) {
        Ok(ids) => {
            if let Err(e) = sweep_member_markers(ifindex, &ids, lock) {
                warnings.push(("remove_stale_markers", e.to_string()));
            }
        }
        Err(e) => warnings.push(("list_chain_members", e.to_string())),
    }
    for w in warnings {
        tracing::warn!(
            device = %dev.name(),
            operation = w.0,
            error = %w.1,
            action = "retry at the next start",
            "XDP classifier chain cleanup failed"
        );
    }
    Ok(dispatcher)
}

fn current_member_ids(if_index: u32) -> Result<Vec<u32>, Box<dyn Error>> {
    let prefix = format!("dispatch-{if_index}-");
    let mut ids = Vec::new();
    for entry in fs::read_dir(BPFFS_XDP_DIR)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            ids.extend(read_members(&entry.path())?.into_iter().map(|(_, id)| id));
        }
    }
    Ok(ids)
}

fn sweep_member_markers(if_index: u32, current: &[u32], _lock: &BpffsLock) -> io::Result<()> {
    for id in marker_ids_any(if_index) {
        if current.contains(&id) || !member_is_dead(if_index, id) {
            continue;
        }
        remove_marker_dir(if_index, id)?;
    }
    Ok(())
}

fn read_dispatcher_config(prog_id: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let fd = bpf_sys::prog_fd_by_id(prog_id)?;
    let info = bpf_sys::prog_info(fd.as_fd())?;
    for map_id in info.map_ids {
        let map_fd = bpf_sys::map_fd_by_id(map_id)?;
        let map = bpf_sys::map_info(map_fd.as_fd())?;
        if map.map_type == bpf_sys::BPF_MAP_TYPE_ARRAY
            && map.name.contains("rodata")
            && (44..=256).contains(&map.value_size)
        {
            return Ok(bpf_sys::map_lookup_first(
                map_fd.as_fd(),
                map.value_size as usize,
            )?);
        }
    }
    Err(format!("dispatcher {prog_id} has no readable .rodata config map").into())
}

fn read_members(dir: &Path) -> Result<Vec<(String, u32)>, Box<dyn Error>> {
    let mut members = Vec::new();
    for slot in 0..MAX_DISPATCHER_SLOTS {
        let prog = dir.join(format!("prog{slot}-prog"));
        if !prog.exists() {
            break;
        }
        let fd = bpf_sys::obj_get(&prog)?;
        let info = bpf_sys::prog_info(fd.as_fd())?;
        members.push((info.name, info.id));
    }
    Ok(members)
}
