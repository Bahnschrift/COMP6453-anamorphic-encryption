use crypto_bigint::{NonZero, RandomMod, Uint};
use rand::Rng;

/// Generates a random integer in the range [lower_bound, modulus).
///
/// # Panics:
/// - If `lower_bound >= modulus`
pub fn random_mod_lb<const LIMBS: usize, R: Rng + ?Sized>(
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
