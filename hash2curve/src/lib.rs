#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::mod_module_files,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    unused_attributes,
    unused_imports,
    unused_mut,
    unused_must_use
)]

mod expand_msg;
mod isogeny;
mod map2curve;
mod oprf;
mod osswu;

pub use expand_msg::{xmd::*, xof::*, *};
pub use isogeny::*;
pub use map2curve::*;
pub use oprf::*;
pub use osswu::*;

use core::num::NonZeroU16;
use digest::{
    array::{Array, ArraySize},
    consts::{U1, U2},
    typenum::{Unsigned, NonZero},
};

/// A hash to curve suite.
///
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-suites-for-hashing>
pub trait Suite {
    /// The ID of the suite.
    const ID: &'static str;

    /// The point type used in the suite.
    type Point: MapToCurve;

    /// The security level of the suite.
    type SecurityLevel: Unsigned;

    /// The expand message trait used in the suite.
    type ExpandMsg: ExpandMsg<Self::SecurityLevel>;

    /// Computes the hash to curve routine.
    ///
    /// Equivalent of [`hash_from_bytes`], but using the suite's parameters.
    /// See that function for more details.
    fn hash_from_bytes(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        hash_from_bytes::<Self::ExpandMsg, Self::SecurityLevel, Self::Point>(msg, dst)
    }

    /// Computes the encode to curve routine.
    ///
    /// Equivalent of [`encode_from_bytes`], but using the suite's parameters.
    /// See that function for more details.
    fn encode_from_bytes(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        encode_from_bytes::<Self::ExpandMsg, Self::SecurityLevel, Self::Point>(msg, dst)
    }
}

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
pub fn hash_to_field<E, K, T, C>(data: &[&[u8]], domain: &[&[u8]]) -> Option<Array<T, C>>
where
    E: ExpandMsg<K>,
    T: FromOkm + Default,
    C: ArraySize,
{
    let len_in_bytes = T::Length::USIZE
        .checked_mul(C::USIZE)
        .and_then(|len| len.try_into().ok())
        .and_then(NonZeroU16::new)?;
    let mut tmp = Array::<u8, <T as FromOkm>::Length>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;

    let mut out = Array::<T, C>::default();
    for o in out.iter_mut() {
        expander.fill_bytes(&mut tmp);
        *o = T::from_okm(&tmp);
    }

    Some(out)
}

/// Computes the hash to curve routine.
///
/// From <https://www.rfc-editor.org/rfc/rfc9380.html>:
///
/// > Uniform encoding from byte strings to points in G.
/// > That is, the distribution of its output is statistically close
/// > to uniform in G.
/// > This function is suitable for most applications requiring a random
/// > oracle returning points in G assuming a cryptographically secure
/// > hash function is used.
///
/// # Fails
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional failing conditions:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`
///
/// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::ExpandMsgXof
pub fn hash_from_bytes<X, K, P>(msg: &[&[u8]], dst: &[&[u8]]) -> Option<P>
where
    X: ExpandMsg<K>,
    P: MapToCurve,
{
    let u = hash_to_field::<X, _, P::FieldElement, U2>(msg, dst)?;
    let q0 = P::map_to_curve(u[0]);
    let q1 = P::map_to_curve(u[1]);
    Some(P::add_and_map_to_subgroup(q0, q1))
}

/// Computes the encode to curve routine.
///
/// From <https://www.rfc-editor.org/rfc/rfc9380.html>:
///
/// > Nonuniform encoding from byte strings to
/// > points in G. That is, the distribution of its output is not
/// > uniformly random in G: the set of possible outputs of
/// > encode_to_curve is only a fraction of the points in G, and some
/// > points in this set are more likely to be output than others.
///
/// # Fails
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional failing conditions:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = <Self::FieldElement as FromOkm>::Length`
///
/// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::ExpandMsgXof
pub fn encode_from_bytes<X, K, P>(msg: &[&[u8]], dst: &[&[u8]]) -> Option<P>
where
    X: ExpandMsg<K>,
    P: MapToCurve,
{
    let u = hash_to_field::<X, _, P::FieldElement, U1>(msg, dst)?;
    let q0 = P::map_to_curve(u[0]);
    Some(P::map_to_subgroup(q0))
}
