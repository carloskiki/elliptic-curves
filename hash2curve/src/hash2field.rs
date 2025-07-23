//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;


pub use expand_msg::{xmd::*, xof::*, *};

use elliptic_curve::array::{
    Array, ArraySize,
    typenum::NonZero,
};

/// The trait for helping to convert to a field element.
pub trait FromOkm {
    /// The number of bytes needed to convert to a field element.
    type Length: ArraySize + NonZero;

    /// Convert a byte sequence into a field element.
    fn from_okm(data: &Array<u8, Self::Length>) -> Self;
}
