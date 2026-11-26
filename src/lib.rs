//! AF_XDP for Linux services.
//!
//! - One XDP hook shared by every program on the host that follows this library's
//!   protocol: a libxdp-compatible dispatcher, a marker per member, ownership records
//!   for steering rules, and cleanup after a process that died.
//! - Send engines: transmit loops on dedicated cores, bond-aware, with VLAN and GRE.
//! - Receive engines: UDP receive by port, and a QUIC socket for quinn endpoints.
//!
//! The modules at the crate root keep the layout of Agave's `xdp` crate, from which
//! many of them derive, so its changes merge file by file; see NOTICE.

#[cfg(target_os = "linux")]
pub mod bond;
#[cfg(target_os = "linux")]
pub mod bpf_sys;
#[cfg(target_os = "linux")]
pub mod cpu_affinity;
#[cfg(target_os = "linux")]
pub mod dispatcher;
#[cfg(target_os = "linux")]
pub mod ethtool;
#[cfg(target_os = "linux")]
pub mod objects;

macro_rules! agave_derived {
    ($($(#[$attr:meta])* $vis:vis mod $name:ident;)*) => {$(
        $(#[$attr])*
        #[allow(
            clippy::missing_const_for_fn,
            clippy::trivially_copy_pass_by_ref,
            clippy::clone_on_ref_ptr,
            clippy::unnecessary_cast,
            clippy::too_many_arguments
        )]
        $vis mod $name;
    )*};
}

agave_derived! {
    #[cfg(target_os = "linux")]
    pub mod device;
    pub mod ecn_codepoint;
    #[cfg(target_os = "linux")]
    pub mod gre;
    #[cfg(target_os = "linux")]
    pub(crate) mod lpm;
    #[cfg(target_os = "linux")]
    pub(crate) mod neighbors;
    #[cfg(target_os = "linux")]
    pub mod netlink;
    #[cfg(target_os = "linux")]
    pub mod packet;
    #[cfg(target_os = "linux")]
    mod program;
    #[cfg(target_os = "linux")]
    pub mod route;
    #[cfg(target_os = "linux")]
    pub mod route_monitor;
    #[cfg(target_os = "linux")]
    pub mod socket;
    pub mod transmitter;
    #[cfg(target_os = "linux")]
    pub mod tx_loop;
    #[cfg(target_os = "linux")]
    pub mod umem;
}

#[cfg(target_os = "linux")]
pub mod classifier;

#[cfg(target_os = "linux")]
pub mod plan;
#[cfg(target_os = "linux")]
pub mod queue_alloc;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod rx;
#[cfg(target_os = "linux")]
pub mod rx_tx;

#[cfg(target_os = "linux")]
pub use program::{LoadXdpProgramError, add_rx_port, load_rx_program, load_xdp_program, register_xsk};

mod cleanup;
mod context;
mod error;
#[cfg(target_os = "linux")]
pub(crate) mod installer;
mod metrics;
#[cfg(target_os = "linux")]
mod monitor;
#[cfg(target_os = "linux")]
pub(crate) mod nic;
#[cfg(target_os = "linux")]
pub(crate) mod pace;
pub(crate) mod quic;
#[cfg(target_os = "linux")]
pub(crate) mod record;
mod settings;
#[cfg(target_os = "linux")]
pub(crate) mod setup;
pub(crate) mod slaves;

pub use cleanup::{
    CleanupFailure, CleanupOutcome, CleanupReport, Detached, ReapedMembers, ReapedRecord,
    UnattributedProgram, UnmarkedMembers, reap_dead_leftovers,
};
pub use context::{XdpContext, XdpSummary};
pub use error::{DropReason, XdpConfigError, XdpError, XdpFailure};
pub use metrics::{DropCounts, PumpMetrics, SocketMetrics, XdpStatistics};
#[cfg(not(target_os = "linux"))]
pub use other_socket::XdpQuicSocket;
pub use settings::{EndpointSpec, XdpMode, XdpSettings};
#[cfg(target_os = "linux")]
pub use quic::socket::XdpQuicSocket;

#[cfg(not(target_os = "linux"))]
mod other_socket {
    use {
        crate::{SocketMetrics, XdpStatistics},
        quinn::{
            AsyncUdpSocket, UdpPoller,
            udp::{RecvMeta, Transmit},
        },
        std::{
            io::{self, IoSliceMut},
            net::SocketAddr,
            pin::Pin,
            sync::Arc,
            task::{Context, Poll},
        },
    };

    /// AF_XDP exists on Linux only; no value of this type can be built elsewhere.
    #[derive(Debug)]
    pub struct XdpQuicSocket {
        never: std::convert::Infallible,
    }

    impl XdpQuicSocket {
        pub fn needs_service(&self) -> bool {
            match self.never {}
        }

        pub fn wake(&self) {
            match self.never {}
        }

        pub fn metrics(&self) -> SocketMetrics {
            match self.never {}
        }

        pub fn xdp_statistics(&self) -> io::Result<XdpStatistics> {
            match self.never {}
        }
    }

    impl AsyncUdpSocket for XdpQuicSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            match self.never {}
        }

        fn try_send(&self, _transmit: &Transmit<'_>) -> io::Result<()> {
            match self.never {}
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            match self.never {}
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            match self.never {}
        }
    }
}

use std::{io, net::Ipv4Addr, num::ParseIntError};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InterfaceIpError {
    #[error("invalid bond master index for {interface}: {source}")]
    InvalidBondMasterIndex {
        interface: String,
        source: ParseIntError,
    },
    #[error("failed to resolve bond master IPv4 for {interface} (index {index}): {source}")]
    ResolveBondMasterIp {
        interface: String,
        index: u32,
        source: io::Error,
    },
    #[error("failed to resolve IPv4 address of {interface}: {source}")]
    ResolveInterfaceIp {
        interface: String,
        source: io::Error,
    },
}

/// Returns the IPv4 address of the specified network interface.
///
/// If the interface is part of a bonded interface, returns the master's IPv4 address.
#[cfg(target_os = "linux")]
pub fn interface_ipv4(interface: &str) -> Result<Ipv4Addr, InterfaceIpError> {
    if let Some(ip) = crate::transmitter::read_bond_master_ip(interface)? {
        Ok(ip)
    } else {
        crate::device::NetworkDevice::new(interface)
            .and_then(|device| device.ipv4_addr())
            .map_err(|source| InterfaceIpError::ResolveInterfaceIp {
                interface: interface.to_string(),
                source,
            })
    }
}

#[cfg(not(target_os = "linux"))]
pub fn interface_ipv4(_interface: &str) -> Result<Ipv4Addr, InterfaceIpError> {
    unimplemented!()
}

/// Returns the IPv4 address of the device associated with the default route.
#[cfg(target_os = "linux")]
pub fn default_device_ipv4() -> Result<Ipv4Addr, io::Error> {
    crate::device::NetworkDevice::new_from_default_route()
        .map_err(io::Error::other)?
        .ipv4_addr()
}

#[cfg(not(target_os = "linux"))]
pub fn default_device_ipv4() -> Result<Ipv4Addr, io::Error> {
    unimplemented!()
}
