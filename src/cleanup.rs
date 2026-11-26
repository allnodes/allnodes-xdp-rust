#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::error::XdpError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReapedRecord {
    pub path: String,
    /// Rules deleted; entries already gone or changed are only dropped.
    pub rule_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReapedMembers {
    pub ifindex: u32,
    /// `None` when the interface is gone.
    pub device: Option<String>,
    pub member_ids: Vec<u32>,
    /// Presence markers only: members in no attached chain, or on an interface that is gone.
    pub marker_ids: Vec<u32>,
    pub detached: Option<Detached>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Detached {
    pub prog_id: u32,
    /// Driver mode; else generic (skb).
    pub drv: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupFailure {
    pub operation: &'static str,
    pub path: Option<String>,
    pub ifindex: Option<u32>,
    pub device: Option<String>,
    pub error: String,
    pub remedy: String,
}

impl CleanupFailure {
    pub(crate) fn from_error(operation: &'static str, path: Option<String>, e: XdpError) -> Self {
        match e {
            XdpError::Setup {
                interface,
                device,
                endpoint,
                reason,
                remedy,
            } => Self {
                operation,
                path,
                ifindex: None,
                device: device.or_else(|| (interface != NO_INTERFACE).then_some(interface)),
                error: match endpoint {
                    Some(ep) => format!("{ep}: {reason}"),
                    None => reason,
                },
                remedy,
            },
            other => Self {
                operation,
                path,
                ifindex: None,
                device: None,
                error: other.to_string(),
                remedy: RETRY.into(),
            },
        }
    }
}

/// Members with no presence marker: the owner is unknown, so they are left alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmarkedMembers {
    pub ifindex: u32,
    pub device: Option<String>,
    pub member_ids: Vec<u32>,
}

/// Attached program with no pin directory in this bpffs; never touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnattributedProgram {
    pub ifindex: u32,
    pub device: Option<String>,
    pub prog_id: u32,
    pub drv: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub records: Vec<ReapedRecord>,
    pub members: Vec<ReapedMembers>,
    pub failures: Vec<CleanupFailure>,
    pub unmarked: Vec<UnmarkedMembers>,
    pub unattributed: Vec<UnattributedProgram>,
    /// Read-only checks that could not be made.
    pub unchecked: Vec<CleanupFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupOutcome {
    Clean,
    /// Wins over `Unverified`.
    Failed,
    /// Something could not be attributed: needs a human.
    Unverified,
}

impl CleanupReport {
    /// Pin directories of a detached dispatcher are not examined.
    pub fn nothing_removable(&self) -> bool {
        self.records.is_empty()
            && self.members.is_empty()
            && self.failures.is_empty()
            && self.unverified_count() == 0
    }

    pub const fn complete(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn unverified_count(&self) -> usize {
        self.unmarked
            .iter()
            .map(|m| m.member_ids.len())
            .sum::<usize>()
            + self.unattributed.len()
            + self.unchecked.len()
    }

    pub fn outcome(&self) -> CleanupOutcome {
        if !self.failures.is_empty() {
            CleanupOutcome::Failed
        } else if self.unverified_count() > 0 {
            CleanupOutcome::Unverified
        } else {
            CleanupOutcome::Clean
        }
    }

    pub fn rule_count(&self) -> usize {
        self.records.iter().map(|r| r.rule_count).sum()
    }

    pub fn member_count(&self) -> usize {
        self.members.iter().map(|m| m.member_ids.len()).sum()
    }

    pub fn marker_count(&self) -> usize {
        self.members.iter().map(|m| m.marker_ids.len()).sum()
    }
}

pub(crate) const NO_INTERFACE: &str = "-";
const RETRY: &str =
    "run the cleanup again; what is left is retried there and at the next XDP start";
pub(crate) const CLEANUP_CAPS: [&str; 4] =
    ["CAP_NET_ADMIN", "CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN"];

pub(crate) fn caps_error(missing: &[&str]) -> Option<XdpError> {
    if missing.is_empty() {
        return None;
    }
    Some(XdpError::Setup {
        interface: NO_INTERFACE.into(),
        device: None,
        endpoint: None,
        reason: format!("the process lacks {}", missing.join(", ")),
        remedy: format!(
            "run the cleanup as root, or grant all of {}",
            CLEANUP_CAPS.join(" ")
        ),
    })
}

/// Removes leftovers of every dead process using this library; `Err` only when nothing could be looked at.
/// Takes the bpffs lock and blocks: do not call while holding it or while setting up a context.
pub fn reap_dead_leftovers() -> Result<CleanupReport, XdpError> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(XdpError::Unsupported)
    }
}

type ScanResult<T> = Result<Vec<T>, Box<dyn std::error::Error>>;

fn unchecked(
    operation: &'static str,
    path: Option<&str>,
    e: &dyn std::error::Error,
) -> CleanupFailure {
    CleanupFailure {
        operation,
        path: path.map(str::to_string),
        ifindex: None,
        device: None,
        error: e.to_string(),
        remedy: RETRY.into(),
    }
}

fn add_unmarked(
    report: &mut CleanupReport,
    scan: ScanResult<(u32, Vec<u32>)>,
    name: impl Fn(u32) -> Option<String>,
) {
    match scan {
        Ok(found) => {
            report.unmarked.extend(
                found
                    .into_iter()
                    .map(|(ifindex, member_ids)| UnmarkedMembers {
                        ifindex,
                        device: name(ifindex),
                        member_ids,
                    }),
            )
        }
        Err(e) => {
            report
                .unchecked
                .push(unchecked("list_chain_members", Some(BPFFS_DIR), e.as_ref()))
        }
    }
}

fn add_unattributed(
    report: &mut CleanupReport,
    scan: ScanResult<(u32, u32, bool)>,
    name: impl Fn(u32) -> Option<String>,
) {
    match scan {
        Ok(found) => {
            report
                .unattributed
                .extend(
                    found
                        .into_iter()
                        .map(|(ifindex, prog_id, drv)| UnattributedProgram {
                            ifindex,
                            device: name(ifindex),
                            prog_id,
                            drv,
                        }),
                )
        }
        Err(e) => report
            .unchecked
            .push(unchecked("list_attached_programs", None, e.as_ref())),
    }
}

const BPFFS_DIR: &str = "/sys/fs/bpf/xdp";

#[cfg(target_os = "linux")]
mod linux {
    use {
        super::*,
        crate::{
            context::{SETUP_LOCK_WAIT, take_setup_lock},
            nic::EthtoolNic,
            record,
            setup::{self, setup_err},
            device::NetworkDevice,
            dispatcher::{self, BPFFS_XDP_DIR, BpffsLock},
        },
        std::{io, path::Path},
    };

    const BPFFS: &str = "/sys/fs/bpf";
    const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
    const ACCESS: &str = "run the cleanup as root (or with CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN) in \
                          the mount namespace the dead process ran in, where its bpf filesystem is mounted at /sys/fs/bpf";
    const MEMBER_REMEDY: &str = "if nothing else uses XDP on that interface, detach XDP from it (`ip link set dev NAME \
                                 xdp off` with that name); otherwise run the cleanup again";

    fn device_name(ifindex: u32) -> Option<String> {
        NetworkDevice::new_from_index(ifindex)
            .ok()
            .map(|d| d.name().to_string())
    }

    fn bpffs_present() -> Result<bool, XdpError> {
        let err = |reason: String| setup_err(NO_INTERFACE, None, None, reason, ACCESS);
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c"/sys/fs/bpf".as_ptr(), &mut st) } != 0 {
            return Err(err(format!(
                "cannot open {BPFFS}: {}",
                io::Error::last_os_error()
            )));
        }
        if (st.f_type as u64) & 0xffff_ffff != BPF_FS_MAGIC {
            return Err(err(format!(
                "{BPFFS} is not a bpf filesystem here, so the ownership records and chain markers cannot be read"
            )));
        }
        match std::fs::symlink_metadata(BPFFS_XDP_DIR) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(err(format!("cannot open {BPFFS_XDP_DIR}: {e}"))),
        }
    }

    pub(super) fn for_cleanup(e: XdpError) -> XdpError {
        match e {
            XdpError::Setup {
                interface,
                device,
                endpoint,
                reason,
                remedy,
            } => XdpError::Setup {
                interface,
                device,
                endpoint,
                reason,
                remedy: remedy.replace("then restart", "then run the cleanup again"),
            },
            other => other,
        }
    }

    pub(super) fn run() -> Result<CleanupReport, XdpError> {
        let mut report = CleanupReport::default();
        if !bpffs_present()? {
            find_unattributed(&mut report);
            return Ok(report);
        }
        if let Some(e) = caps_error(&setup::missing_caps_of(NO_INTERFACE, &CLEANUP_CAPS)?) {
            return Err(e);
        }
        let try_lock = || BpffsLock::try_acquire().map_err(|e| e.to_string());
        let lock = take_setup_lock(NO_INTERFACE, SETUP_LOCK_WAIT, try_lock).map_err(for_cleanup)?;
        reap_records(&lock, &mut report);
        reap_members(&lock, &mut report);
        add_unmarked(
            &mut report,
            dispatcher::unmarked_members(&lock),
            device_name,
        );
        find_unattributed(&mut report);
        drop(lock);
        Ok(report)
    }

    fn find_unattributed(report: &mut CleanupReport) {
        add_unattributed(report, dispatcher::unattributed_programs(), device_name);
    }

    fn reap_records(lock: &BpffsLock, report: &mut CleanupReport) {
        let owners = match record::dead_owners(Path::new(BPFFS_XDP_DIR), lock) {
            Ok(owners) => owners,
            Err(e) => {
                report.failures.push(CleanupFailure::from_error(
                    "list_records",
                    Some(BPFFS_XDP_DIR.into()),
                    e,
                ));
                return;
            }
        };
        for owner in owners {
            let path = owner.dir().display().to_string();
            match setup::reap_owner(NO_INTERFACE, &EthtoolNic, owner) {
                Ok((path, rule_count)) => report.records.push(ReapedRecord { path, rule_count }),
                Err(e) => report.failures.push(CleanupFailure::from_error(
                    "remove_dead_record",
                    Some(path),
                    e,
                )),
            }
        }
    }

    fn reap_members(lock: &BpffsLock, report: &mut CleanupReport) {
        match dispatcher::reap_dead_members_everywhere(lock, &[], &mut || {}) {
            Ok((removed, warnings)) => {
                for r in removed
                    .into_iter()
                    .filter(|r| !r.members.is_empty() || !r.markers.is_empty())
                {
                    report.members.push(ReapedMembers {
                        ifindex: r.ifindex,
                        device: device_name(r.ifindex),
                        member_ids: r.members,
                        marker_ids: r.markers,
                        detached: r.detached.map(|(prog_id, drv)| Detached { prog_id, drv }),
                    });
                }
                for w in warnings {
                    report.failures.push(CleanupFailure {
                        operation: "remove_dead_members",
                        path: None,
                        ifindex: Some(w.ifindex),
                        device: w.device,
                        error: w.error,
                        remedy: MEMBER_REMEDY.into(),
                    });
                }
            }
            Err(e) => report.failures.push(CleanupFailure {
                operation: "remove_dead_members",
                path: Some(BPFFS_XDP_DIR.into()),
                ifindex: None,
                device: None,
                error: e.to_string(),
                remedy: RETRY.into(),
            }),
        }
    }
}
