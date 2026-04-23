//! # PKE Helpers
//!
//! This module provides helper functions for public key encryption, such as converting between
//! strings/bytes and `crypto_bigint` types.

use crypto_bigint::{BitOps, NonZero, RandomMod, Uint};
use rand::Rng;

/// Generates a random integer in the range [lower_bound, modulus).
///
/// # Panics:
/// - If `lower_bound >= modulus`
pub(crate) fn random_mod_lb<const LIMBS: usize, R: Rng + ?Sized>(
    rng: &mut R,
    lower_bound: Uint<LIMBS>,
    modulus: NonZero<Uint<LIMBS>>,
) -> Uint<LIMBS> {
    if lower_bound >= *modulus {
        panic!("Lower bound >= modulus! ({} >= {})", lower_bound, modulus)
    }

    // This won't panic, since modulus is at least 1 more than lower_bound
    let scaled_modulus = NonZero::new(*modulus - lower_bound).unwrap();

    // Generate a number in [0, modulus - lower_bound)
    let r = Uint::random_mod_vartime(rng, &scaled_modulus);

    r + lower_bound
}

/// Converts some array of bytes to a BigInt with the specified number of limbs.
///
/// This probably breaks if you have any zero bytes... idk haven't tested that.
///
/// # Examples
///
/// ```
/// use anamorphic_encryption::helpers::{bigint_to_bytes, bytes_to_bigint};
/// use crypto_bigint::U256;
///
/// let s = "incredible string";
/// let e: U256 = bytes_to_bigint(s.as_bytes()).expect("Should fit in a 256 bit int");
/// let d = String::from_utf8(bigint_to_bytes(e)).unwrap();
/// assert_eq!(s, d);
/// ```
pub fn bytes_to_bigint<const LIMBS: usize>(s: &[u8]) -> Option<Uint<LIMBS>> {
    if s.len() > LIMBS * 8 {
        return None;
    }

    Some(Uint::<LIMBS>::from_le_slice(
        s.iter()
            .chain(std::iter::repeat(&0u8))
            .take(LIMBS * 8)
            .cloned()
            .collect::<Vec<u8>>()
            .as_slice(),
    ))
}

/// Reverse of [bytes_to_bigint]
pub fn bigint_to_bytes<const LIMBS: usize>(n: Uint<LIMBS>) -> Vec<u8> {
    n.to_le_bytes()[..((n.bits_precision() - n.leading_zeros()).div_ceil(8)) as usize].to_vec()
}

#[cfg(test)]
mod tests {
    use crypto_bigint::U256;

    use crate::helpers::{bigint_to_bytes, bytes_to_bigint};

    #[test]
    fn test_enc_dec_string() {
        let s = "incredible string";
        let e: U256 = bytes_to_bigint(s.as_bytes()).expect("Should fit in a 256 bit int");
        let d = String::from_utf8(bigint_to_bytes(e)).unwrap();
        assert_eq!(s, d);
    }
}
