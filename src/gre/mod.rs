// Derived from Agave's `xdp` crate (https://github.com/anza-xyz/agave, Apache-2.0);
// changed by Allnodes. See NOTICE.
pub mod packet;

pub use packet::{GreHeader, PacketError, construct_gre_packet, gre_packet_size};
