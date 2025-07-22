use digest::FixedOutput;
use digest::Update;
use elliptic_curve::{
    PrimeCurveArithmetic,
    array::typenum::IsLess,
    consts::{True, U65536},
};

use crate::ExpandMsg;
use crate::MapToCurve;

/// Elliptic curve parameters used by OPRF.
pub trait OprfParameters: PrimeCurveArithmetic<ProjectivePoint: MapToCurve> {
    /// The `ID` parameter which identifies a particular elliptic curve
    /// as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    const ID: &'static [u8];

    /// The `Hash` parameter which assigns a particular hash function to this
    /// ciphersuite as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    type Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update;

    /// The `expand_message` parameter which assigns a particular algorithm for `HashToGroup`
    /// and `HashToScalar` as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    type ExpandMsg: ExpandMsg<<Self::ProjectivePoint as MapToCurve>::K>;
}
