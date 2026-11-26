
#[repr(C, align(8))]
pub struct Aligned<Bytes: ?Sized>(Bytes);

impl<Bytes: ?Sized> std::ops::Deref for Aligned<Bytes> {
    type Target = Bytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub static DISPATCHER: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/objects/allnodes-xdp-dispatcher"
)));

pub static CLASSIFIER: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/objects/allnodes-xdp-classifier"
)));
