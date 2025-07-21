//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroU16;

pub use expand_msg::{xmd::*, xof::*, *};

use elliptic_curve::array::{
    Array, ArraySize,
    typenum::{NonZero, Unsigned},
};

/// The trait for helping to convert to a field element.
pub trait FromOkm {
    /// The number of bytes needed to convert to a field element.
    type Length: ArraySize + NonZero;

    /// Convert a byte sequence into a field element.
    fn from_okm(data: &Array<u8, Self::Length>) -> Self;
}

/// Convert an arbitrary byte sequence into a field element.
///
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-hash_to_field-implementatio>
///
/// # Errors
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional errors:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = T::Length * out.len()`
///
/// [`ExpandMsgXmd`]: crate::hash2field::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::hash2field::ExpandMsgXof
#[doc(hidden)]
pub fn hash_to_field<'dst, const N: usize, E, K, T>(
    data: &[&[u8]],
    domain: &'dst [&[u8]],
) -> Result<[T; N], E::Error>
where
    E: ExpandMsg<'dst, K>,
    T: FromOkm + Default,
{
    const { assert!(T::Length::USIZE * N <= u16::MAX as usize && T::Length::USIZE * N != 0) }
    let len_in_bytes =
        NonZeroU16::new(T::Length::U16 * N as u16).expect("should be checked in const assert");
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    Ok(core::array::from_fn(|_| {
        T::from_okm(&expander.by_ref().take(T::Length::USIZE).collect())
    }))
}
