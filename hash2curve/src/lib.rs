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

mod hash2field;
mod isogeny;
mod map2curve;
mod oprf;
mod osswu;

pub use hash2field::*;
pub use isogeny::*;
pub use map2curve::*;
pub use oprf::*;
pub use osswu::*;

use elliptic_curve::Result;

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
/// # Errors
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional errors:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`
///
/// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::ExpandMsgXof
pub fn hash_to_curve<X, P>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<P>
where
    P: MapToCurve,
    X: ExpandMsg<P::K>,
{
    let [u0, u1] = hash_to_field::<2, X, _, P::FieldElement>(msg, dst)?;
    let q0 = P::map_to_curve(u0);
    let q1 = P::map_to_curve(u1);
    Ok(P::add_and_map_to_subgroup(q0, q1))
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
/// # Errors
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional errors:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = <Self::FieldElement as FromOkm>::Length`
///
/// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::ExpandMsgXof
pub fn encode_to_curve<X, P>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<P>
where
    P: MapToCurve,
    X: ExpandMsg<P::K>,
{
    let [u] = hash_to_field::<1, X, _, P::FieldElement>(msg, dst)?;
    let q0 = P::map_to_curve(u);
    Ok(P::map_to_subgroup(q0))
}
