//! `expand_message_xof` for the `ExpandMsg` trait

use super::{Domain, ExpandMsg};
use core::{fmt, num::NonZero, ops::Mul};
use digest::XofReader;
use digest::{
    CollisionResistance, ExtendableOutput, HashMarker, Update, typenum::IsGreaterOrEqual,
};
use elliptic_curve::Result;
use elliptic_curve::array::{
    ArraySize,
    typenum::{Prod, True, U2},
};

/// Implements `expand_message_xof` via the [`ExpandMsg`] trait:
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xof>
///
/// # Errors
/// - `dst` contains no bytes
/// - `dst > 255 && K * 2 > 255`
pub struct ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update + HashMarker,
{
    reader: HashT::Reader,
    length: u16,
}

impl<HashT> fmt::Debug for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update + HashMarker,
    <HashT as ExtendableOutput>::Reader: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXof")
            .field("reader", &self.reader)
            .finish()
    }
}

impl<HashT, K> ExpandMsg<'_, K> for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update + HashMarker,
    // If DST is larger than 255 bytes, the length of the computed DST is calculated by `K * 2`.
    // https://www.rfc-editor.org/rfc/rfc9380.html#section-5.3.1-2.1
    K: Mul<U2, Output: ArraySize>,
    // The collision resistance of `HashT` MUST be at least `K` bits.
    // https://www.rfc-editor.org/rfc/rfc9380.html#section-5.3.2-2.1
    HashT: CollisionResistance<CollisionResistance: IsGreaterOrEqual<K, Output = True>>,
{
    fn expand_message(msg: &[&[u8]], dst: &[&[u8]], len_in_bytes: NonZero<u16>) -> Result<Self> {
        let len_in_bytes = len_in_bytes.get();

        let domain = Domain::<Prod<K, U2>>::xof::<HashT>(dst)?;
        let mut reader = HashT::default();

        for msg in msg {
            reader = reader.chain(msg);
        }

        reader.update(&len_in_bytes.to_be_bytes());
        domain.update_hash(&mut reader);
        reader.update(&[domain.len()]);
        let reader = reader.finalize_xof();
        Ok(Self {
            reader,
            length: len_in_bytes,
        })
    }
}

impl<HashT> Iterator for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update + HashMarker,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.length == 0 {
            return None;
        }
        self.length -= 1;
        let mut buf = [0u8; 1];
        self.reader.read(&mut buf);
        Some(buf[0])
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::Error;

    use super::*;
    use core::mem::size_of;
    use elliptic_curve::array::{
        Array, ArraySize,
        typenum::{IsLess, U16, U32, U128, U65536},
    };
    use hex_literal::hex;
    use sha3::Shake128;

    fn assert_message(msg: &[u8], domain: &Domain<'_, U32>, len_in_bytes: u16, bytes: &[u8]) {
        let msg_len = msg.len();
        assert_eq!(msg, &bytes[..msg_len]);

        let len_in_bytes_len = msg_len + size_of::<u16>();
        assert_eq!(
            len_in_bytes.to_be_bytes(),
            &bytes[msg_len..len_in_bytes_len]
        );

        let dst = len_in_bytes_len + usize::from(domain.len());
        domain.assert(&bytes[len_in_bytes_len..dst]);

        let dst_len = dst + size_of::<u8>();
        assert_eq!([domain.len()], &bytes[dst..dst_len]);

        assert_eq!(dst_len, bytes.len());
    }

    struct TestVector {
        msg: &'static [u8],
        msg_prime: &'static [u8],
        uniform_bytes: &'static [u8],
    }

    impl TestVector {
        #[allow(clippy::panic_in_result_fn)]
        fn assert<HashT, L>(&self, dst: &'static [u8], domain: &Domain<'_, U32>) -> Result<()>
        where
            HashT: Default
                + ExtendableOutput
                + Update
                + HashMarker
                + CollisionResistance<CollisionResistance: IsGreaterOrEqual<U16, Output = True>>,
            L: ArraySize + IsLess<U65536, Output = True>,
        {
            assert_message(self.msg, domain, L::to_u16(), self.msg_prime);

            let expander = <ExpandMsgXof<HashT> as ExpandMsg<U16>>::expand_message(
                &[self.msg],
                &[dst],
                NonZero::new(L::U16).ok_or(Error)?,
            )?;

            let uniform_bytes = Array::<u8, L>::from_iter(expander);
            assert_eq!(uniform_bytes.as_slice(), self.uniform_bytes);
            Ok(())
        }
    }

    #[test]
    fn expand_message_xof_shake_128() -> Result<()> {
        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE128";
        const DST_PRIME: &[u8] =
            &hex!("515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824");

        let dst_prime = Domain::<U32>::xof::<Shake128>(&[DST])?;
        dst_prime.assert_dst(DST_PRIME);

        const TEST_VECTORS_32: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("86518c9cd86581486e9485aa74ab35ba150d1c75c88e26b7043e44e2acd735a2"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("8696af52a4d862417c0763556073f47bc9b9ba43c99b505305cb1ec04a9ab468"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("912c58deac4821c3509dbefa094df54b34b8f5d01a191d1d3108a2c89077acca"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("1adbcc448aef2a0cebc71dac9f756b22e51839d348e031e63b33ebb50faeaf3f"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("df3447cc5f3e9a77da10f819218ddf31342c310778e0e4ef72bbaecee786a4fe"),
            },
        ];

        for test_vector in TEST_VECTORS_32 {
            test_vector.assert::<Shake128, U32>(DST, &dst_prime)?;
        }

        const TEST_VECTORS_128: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("7314ff1a155a2fb99a0171dc71b89ab6e3b2b7d59e38e64419b8b6294d03ffee42491f11370261f436220ef787f8f76f5b26bdcd850071920ce023f3ac46847744f4612b8714db8f5db83205b2e625d95afd7d7b4d3094d3bdde815f52850bb41ead9822e08f22cf41d615a303b0d9dde73263c049a7b9898208003a739a2e57"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("c952f0c8e529ca8824acc6a4cab0e782fc3648c563ddb00da7399f2ae35654f4860ec671db2356ba7baa55a34a9d7f79197b60ddae6e64768a37d699a78323496db3878c8d64d909d0f8a7de4927dcab0d3dbbc26cb20a49eceb0530b431cdf47bc8c0fa3e0d88f53b318b6739fbed7d7634974f1b5c386d6230c76260d5337a"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("19b65ee7afec6ac06a144f2d6134f08eeec185f1a890fe34e68f0e377b7d0312883c048d9b8a1d6ecc3b541cb4987c26f45e0c82691ea299b5e6889bbfe589153016d8131717ba26f07c3c14ffbef1f3eff9752e5b6183f43871a78219a75e7000fbac6a7072e2b83c790a3a5aecd9d14be79f9fd4fb180960a3772e08680495"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("ca1b56861482b16eae0f4a26212112362fcc2d76dcc80c93c4182ed66c5113fe41733ed68be2942a3487394317f3379856f4822a611735e50528a60e7ade8ec8c71670fec6661e2c59a09ed36386513221688b35dc47e3c3111ee8c67ff49579089d661caa29db1ef10eb6eace575bf3dc9806e7c4016bd50f3c0e2a6481ee6d"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824"),
                uniform_bytes: &hex!("9d763a5ce58f65c91531b4100c7266d479a5d9777ba761693d052acd37d149e7ac91c796a10b919cd74a591a1e38719fb91b7203e2af31eac3bff7ead2c195af7d88b8bc0a8adf3d1e90ab9bed6ddc2b7f655dd86c730bdeaea884e73741097142c92f0e3fc1811b699ba593c7fbd81da288a29d423df831652e3a01a9374999"),
            },
        ];

        for test_vector in TEST_VECTORS_128 {
            test_vector.assert::<Shake128, U128>(DST, &dst_prime)?;
        }

        Ok(())
    }

    #[test]
    fn expand_message_xof_shake_128_long() -> Result<()> {
        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE128-long-DST-111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        const DST_PRIME: &[u8] =
            &hex!("acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20");

        let dst_prime = Domain::<U32>::xof::<Shake128>(&[DST])?;
        dst_prime.assert_dst(DST_PRIME);

        const TEST_VECTORS_32: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0020acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("827c6216330a122352312bccc0c8d6e7a146c5257a776dbd9ad9d75cd880fc53"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630020acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("690c8d82c7213b4282c6cb41c00e31ea1d3e2005f93ad19bbf6da40f15790c5c"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390020acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("979e3a15064afbbcf99f62cc09fa9c85028afcf3f825eb0711894dcfc2f57057"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710020acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("c5a9220962d9edc212c063f4f65b609755a1ed96e62f9db5d1fd6adb5a8dc52b"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610020acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("f7b96a5901af5d78ce1d071d9c383cac66a1dfadb508300ec6aeaea0d62d5d62"),
            },
        ];

        for test_vector in TEST_VECTORS_32 {
            test_vector.assert::<Shake128, U32>(DST, &dst_prime)?;
        }

        const TEST_VECTORS_128: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0080acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("3890dbab00a2830be398524b71c2713bbef5f4884ac2e6f070b092effdb19208c7df943dc5dcbaee3094a78c267ef276632ee2c8ea0c05363c94b6348500fae4208345dd3475fe0c834c2beac7fa7bc181692fb728c0a53d809fc8111495222ce0f38468b11becb15b32060218e285c57a60162c2c8bb5b6bded13973cd41819"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630080acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("41b7ffa7a301b5c1441495ebb9774e2a53dbbf4e54b9a1af6a20fd41eafd69ef7b9418599c5545b1ee422f363642b01d4a53449313f68da3e49dddb9cd25b97465170537d45dcbdf92391b5bdff344db4bd06311a05bca7dcd360b6caec849c299133e5c9194f4e15e3e23cfaab4003fab776f6ac0bfae9144c6e2e1c62e7d57"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390080acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("55317e4a21318472cd2290c3082957e1242241d9e0d04f47026f03401643131401071f01aa03038b2783e795bdfa8a3541c194ad5de7cb9c225133e24af6c86e748deb52e560569bd54ef4dac03465111a3a44b0ea490fb36777ff8ea9f1a8a3e8e0de3cf0880b4b2f8dd37d3a85a8b82375aee4fa0e909f9763319b55778e71"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710080acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("19fdd2639f082e31c77717ac9bb032a22ff0958382b2dbb39020cdc78f0da43305414806abf9a561cb2d0067eb2f7bc544482f75623438ed4b4e39dd9e6e2909dd858bd8f1d57cd0fce2d3150d90aa67b4498bdf2df98c0100dd1a173436ba5d0df6be1defb0b2ce55ccd2f4fc05eb7cb2c019c35d5398b85adc676da4238bc7"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610080acb9736c0867fdfbd6385519b90fc8c034b5af04a958973212950132d035792f20"),
                uniform_bytes: &hex!("945373f0b3431a103333ba6a0a34f1efab2702efde41754c4cb1d5216d5b0a92a67458d968562bde7fa6310a83f53dda1383680a276a283438d58ceebfa7ab7ba72499d4a3eddc860595f63c93b1c5e823ea41fc490d938398a26db28f61857698553e93f0574eb8c5017bfed6249491f9976aaa8d23d9485339cc85ca329308"),
            },
        ];

        for test_vector in TEST_VECTORS_128 {
            test_vector.assert::<Shake128, U128>(DST, &dst_prime)?;
        }

        Ok(())
    }

    #[test]
    fn expand_message_xof_shake_256() -> Result<()> {
        use sha3::Shake256;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE256";
        const DST_PRIME: &[u8] =
            &hex!("515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624");

        let dst_prime = Domain::<U32>::xof::<Shake256>(&[DST])?;
        dst_prime.assert_dst(DST_PRIME);

        const TEST_VECTORS_32: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc"),
            },
        ];

        for test_vector in TEST_VECTORS_32 {
            test_vector.assert::<Shake256, U32>(DST, &dst_prime)?;
        }

        const TEST_VECTORS_128: &[TestVector] = &[
            TestVector {
                msg: b"",
                msg_prime: &hex!("0080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("7a1361d2d7d82d79e035b8880c5a3c86c5afa719478c007d96e6c88737a3f631dd74a2c88df79a4cb5e5d9f7504957c70d669ec6bfedc31e01e2bacc4ff3fdf9b6a00b17cc18d9d72ace7d6b81c2e481b4f73f34f9a7505dccbe8f5485f3d20c5409b0310093d5d6492dea4e18aa6979c23c8ea5de01582e9689612afbb353df"),
            },
            TestVector {
                msg: b"abc",
                msg_prime: &hex!("6162630080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("a54303e6b172909783353ab05ef08dd435a558c3197db0c132134649708e0b9b4e34fb99b92a9e9e28fc1f1d8860d85897a8e021e6382f3eea10577f968ff6df6c45fe624ce65ca25932f679a42a404bc3681efe03fcd45ef73bb3a8f79ba784f80f55ea8a3c367408f30381299617f50c8cf8fbb21d0f1e1d70b0131a7b6fbe"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                msg_prime: &hex!("616263646566303132333435363738390080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("e42e4d9538a189316e3154b821c1bafb390f78b2f010ea404e6ac063deb8c0852fcd412e098e231e43427bd2be1330bb47b4039ad57b30ae1fc94e34993b162ff4d695e42d59d9777ea18d3848d9d336c25d2acb93adcad009bcfb9cde12286df267ada283063de0bb1505565b2eb6c90e31c48798ecdc71a71756a9110ff373"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                msg_prime: &hex!("713132385f71717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171710080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("4ac054dda0a38a65d0ecf7afd3c2812300027c8789655e47aecf1ecc1a2426b17444c7482c99e5907afd9c25b991990490bb9c686f43e79b4471a23a703d4b02f23c669737a886a7ec28bddb92c3a98de63ebf878aa363a501a60055c048bea11840c4717beae7eee28c3cfa42857b3d130188571943a7bd747de831bd6444e0"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                msg_prime: &hex!("613531325f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610080515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624"),
                uniform_bytes: &hex!("09afc76d51c2cccbc129c2315df66c2be7295a231203b8ab2dd7f95c2772c68e500bc72e20c602abc9964663b7a03a389be128c56971ce81001a0b875e7fd17822db9d69792ddf6a23a151bf470079c518279aef3e75611f8f828994a9988f4a8a256ddb8bae161e658d5a2a09bcfe839c6396dc06ee5c8ff3c22d3b1f9deb7e"),
            },
        ];

        for test_vector in TEST_VECTORS_128 {
            test_vector.assert::<Shake256, U128>(DST, &dst_prime)?;
        }

        Ok(())
    }
}
