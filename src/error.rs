use std::net::SocketAddr;

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum XdpConfigError {
    #[error("{var}: invalid value '{value}'; expected {expected}")]
    Invalid {
        var: String,
        value: String,
        expected: &'static str,
    },
    #[error("{var} is set but NET_XDP is not enabled; set {}=true or remove {var}", switch_var(.var))]
    RequiresXdp { var: String },
    #[error("{zero_copy_var}=true needs {mode_var}=drv (zero-copy is not available in skb mode)")]
    ZeroCopyNeedsDrv {
        zero_copy_var: String,
        mode_var: String,
    },
}

fn switch_var(var: &str) -> String {
    match var.find("NET_XDP") {
        Some(i) => format!("{}NET_XDP", &var[..i]),
        None => var.to_string(),
    }
}

#[derive(Clone, Debug)]
pub struct XdpFailure {
    pub cause: String,
}

impl std::fmt::Display for XdpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.cause)
    }
}

impl std::error::Error for XdpFailure {}

#[derive(Clone, Debug, thiserror::Error)]
pub enum XdpError {
    #[error(transparent)]
    Config(#[from] XdpConfigError),
    #[error("AF_XDP is supported on Linux only; disable XDP on this platform")]
    Unsupported,
    #[error("{}", fmt_setup(interface, device, endpoint, reason, remedy))]
    Setup {
        interface: String,
        device: Option<String>,
        endpoint: Option<String>,
        reason: String,
        remedy: String,
    },
    #[error("{dest}: unreachable over XDP: {reason}")]
    Unreachable { dest: SocketAddr, reason: String },
    #[error("XDP failed: {}", .0.cause)]
    Failed(XdpFailure),
    /// The context was shut down (not a failure); its endpoints cannot be used any more.
    #[error("{}", fmt_shut_down(interface, endpoint))]
    ShutDown {
        interface: String,
        endpoint: Option<String>,
    },
}

fn fmt_shut_down(interface: &str, endpoint: &Option<String>) -> String {
    match endpoint {
        Some(e) => format!("{interface} {e}: the XDP context was shut down. build a new context"),
        None => format!("{interface}: the XDP context was shut down. build a new context"),
    }
}

fn fmt_setup(
    interface: &str,
    device: &Option<String>,
    endpoint: &Option<String>,
    reason: &str,
    remedy: &str,
) -> String {
    let mut s = interface.to_string();
    if let Some(d) = device {
        s.push('/');
        s.push_str(d);
    }
    if let Some(e) = endpoint {
        s.push(' ');
        s.push_str(e);
    }
    format!("{s}: {reason}. {remedy}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Oversize,
    NoNextHop,
    NoEligibleSlave,
    LinkDown,
    OtherInterface,
    Malformed,
    BadIpChecksum,
    BadUdpChecksum,
    RxBufferTooSmall,
    Bypass,
    InboxFull,
    /// Same-host send: the kernel socket's send buffer is full (`EAGAIN`/`ENOBUFS`).
    KernelBusy,
    KernelSendFailed,
}

impl DropReason {
    pub const COUNT: usize = 13;

    pub const ALL: [Self; Self::COUNT] = [
        Self::Oversize,
        Self::NoNextHop,
        Self::NoEligibleSlave,
        Self::LinkDown,
        Self::OtherInterface,
        Self::Malformed,
        Self::BadIpChecksum,
        Self::BadUdpChecksum,
        Self::RxBufferTooSmall,
        Self::Bypass,
        Self::InboxFull,
        Self::KernelBusy,
        Self::KernelSendFailed,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Oversize => "oversize",
            Self::NoNextHop => "no_next_hop",
            Self::NoEligibleSlave => "no_eligible_slave",
            Self::LinkDown => "link_down",
            Self::OtherInterface => "other_interface",
            Self::Malformed => "malformed",
            Self::BadIpChecksum => "bad_ip_checksum",
            Self::BadUdpChecksum => "bad_udp_checksum",
            Self::RxBufferTooSmall => "rx_buffer_too_small",
            Self::Bypass => "bypass",
            Self::InboxFull => "inbox_full",
            Self::KernelBusy => "kernel_busy",
            Self::KernelSendFailed => "kernel_send_failed",
        }
    }
}
