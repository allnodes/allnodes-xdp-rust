// Derived from Agave's `xdp` crate (https://github.com/anza-xyz/agave, Apache-2.0);
// changed by Allnodes. See NOTICE.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// ECN Capable Transport, codepoint 0.
    Ect0 = 0b10,
    /// ECN Capable Transport, codepoint 1.
    Ect1 = 0b01,
    /// Indicates congestion to the end nodes, set by router.
    Ce = 0b11,
}
