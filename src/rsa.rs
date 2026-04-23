//! # RSA PKE
//!
//! This module contains an implementation of the RSA public key encryption scheme.
//! It supports standard key generation, encryption, and decryption, with
//! optimizations like the Chinese Remainder Theorem (CRT) for decryption.

use std::ops::Mul;
use std::ops::Sub;

use crypto_bigint::modular::FixedMontyForm;
use crypto_bigint::modular::FixedMontyParams;
use crypto_bigint::{NonZero, Odd, Uint};
use crypto_primes::{Flavor, random_prime};
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};

use crate::pke::PKE;

type RandomSeed = [u8; 32];

/// RSA public key.
///
/// Consists of the modulus `n` and the public exponent `e`.
#[derive(Clone, Debug)]
pub struct RsaPK<const MOD_LIMBS: usize> {
    /// Modulus `n = p * q`
    pub n: Uint<MOD_LIMBS>,
    /// Public exponent, typically 65537
    pub e: Uint<1>,
}

/// RSA private key using the CRT representation.
///
/// Fields are based on the second private key representation given by RFC 8017, Section 3.2.
/// This representation enables significantly faster decryption using the Chinese Remainder Theorem.
#[derive(Clone, Debug)]
pub struct RsaSK<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    /// The first prime factor `p`
    pub p: Uint<PRIME_LIMBS>,
    /// The second prime factor `q`
    pub q: Uint<PRIME_LIMBS>,
    /// CRT exponent of `p`: `dP = d mod (p - 1)`
    pub d_p: Uint<PRIME_LIMBS>,
    /// CRT exponent of `q`: `dQ = d mod (q - 1)`
    pub d_q: Uint<PRIME_LIMBS>,
    /// CRT coefficient: `qInv = q^-1 mod p`
    pub q_inv: Uint<PRIME_LIMBS>,
}

/// Standard RSA implementation.
///
/// RSA is an asymmetric cryptographic algorithm that relies on the difficulty of
/// factoring the product of two large prime numbers.
///
/// # Example usage
/// ```
/// use crypto_bigint::Uint;
/// use anamorphic_encryption::pke::PKE;
/// use anamorphic_encryption::rsa::RSA;
///
/// // Create RSA-2048 (32 limbs of 64 bits each for the 2048-bit modulus)
/// let mut rsa = RSA::<32, 16>::new();
/// let (pk, sk) = rsa.r#gen();
///
/// let m = Uint::<32>::from(18u8);
/// let c = rsa.enc(&m, &pk);
/// let d = rsa.dec(&c, &sk);
/// assert_eq!(m, d);
/// ```
///
/// # Panics:
/// - Panics at compile time if the modulus size (`MOD_LIMBS`) is not at least twice
///   the size of the prime factors (`PRIME_LIMBS`).
#[derive(Debug)]
pub struct RSA<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    rng: ChaCha20Rng,
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> RSA<MOD_LIMBS, PRIME_LIMBS> {
    const ASSERT_LIMBS_RATIO: () = assert!(
        MOD_LIMBS >= 2 * PRIME_LIMBS,
        "Modulus must be at least twice the size of the prime factors"
    );

    /// Creates a new randomly seeded `RSA<MOD_LIMBS, PRIME_LIMBS>`.
    pub fn new() -> Self {
        // Trigger the compile-time assertion
        let _ = Self::ASSERT_LIMBS_RATIO;
        Self {
            rng: ChaCha20Rng::from_seed(rand::rng().random()),
        }
    }

    /// Creates a new seeded `RSA<MOD_LIMBS, PRIME_LIMBS>`
    ///
    /// # Example usage
    /// ```
    /// use anamorphic_encryption::pke::PKE;
    /// use anamorphic_encryption::rsa::RSA;
    ///
    /// let seed = [42u8; 32];
    /// let mut rsa1 = RSA::<32, 16>::new_seeded(seed);
    /// let (pk1, sk1) = rsa1.r#gen();
    ///
    /// let mut rsa2 = RSA::<32, 16>::new_seeded(seed);
    /// let (pk2, sk2) = rsa2.r#gen();
    ///
    /// // Same seed produces the same key pair
    /// assert_eq!(pk1.n, pk2.n);
    /// ```
    pub fn new_seeded(seed: RandomSeed) -> Self {
        let _ = Self::ASSERT_LIMBS_RATIO;
        Self {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> PKE for RSA<MOD_LIMBS, PRIME_LIMBS> {
    type PK = RsaPK<MOD_LIMBS>;
    type SK = RsaSK<MOD_LIMBS, PRIME_LIMBS>;
    type M = Uint<MOD_LIMBS>;
    type C = Uint<MOD_LIMBS>;

    /// Generates a new RSA key pair.
    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        let e: Uint<1> = Uint::from_u64(65537);

        loop {
            let p = random_prime::<Uint<PRIME_LIMBS>, _>(
                &mut self.rng,
                Flavor::Any,
                (PRIME_LIMBS * 64) as u32,
            );
            let q = random_prime::<Uint<PRIME_LIMBS>, _>(
                &mut self.rng,
                Flavor::Any,
                (PRIME_LIMBS * 64) as u32,
            );

            // We need to ensure p > q
            if p == q {
                continue;
            }
            // Swap them if q > p
            let (p, q) = if q > p { (q, p) } else { (p, q) };

            // n = p * q
            let n = p.resize().mul(&q.resize::<MOD_LIMBS>());

            let p_minus_1 = NonZero::new(p.sub(&Uint::ONE)).unwrap();
            let q_minus_1 = NonZero::new(q.sub(&Uint::ONE)).unwrap();

            // d = e^-1 mod phi(N)
            // phi(n) = (p-1)*(q-1)
            let phi_n: Uint<MOD_LIMBS> = p_minus_1.resize().mul(&q_minus_1.resize::<MOD_LIMBS>());
            let phi_n_nz = NonZero::new(phi_n).unwrap();

            // e and phi(n) should be coprime
            // Since e is prime and we ensured p and q are not factors of e,
            // gcd(e, phi(n)) is almost always 1, but if not, we continue to try another pair of primes.
            let d_opt = e.resize().invert_mod(&phi_n_nz);
            if d_opt.is_none().into() {
                continue;
            }
            let d = d_opt.unwrap();

            // dP = d mod (p - 1)
            let d_p = d.rem(&p_minus_1);

            // dQ = d mod (q - 1)
            let d_q = d.rem(&q_minus_1);

            // qInv = q^-1 mod p
            // This won't panic since p > 0
            let p_nz = NonZero::new(p).unwrap();
            // This won't panic since p and q are coprime
            let q_inv = q.invert_mod(&p_nz).unwrap();

            let pk = RsaPK { n, e };
            let sk = RsaSK {
                p,
                q,
                d_p,
                d_q,
                q_inv,
            };

            return (pk, sk);
        }
    }

    /// Encrypts a message using the RSA public key.
    ///
    /// # Panics
    /// - Panics if the modulus `n` is even. Standard RSA moduli are always the product
    ///   of two large primes and thus odd.
    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C {
        // C = M^e mod N
        let mod_odd = Odd::new(pk.n).unwrap();
        let params = FixedMontyParams::new(mod_odd);

        let m_res = FixedMontyForm::new(m, &params);
        let e_mod = pk.e.resize::<MOD_LIMBS>();

        m_res.pow(&e_mod).retrieve()
    }

    /// Decrypts a ciphertext using the RSA private key (CRT optimized).
    ///
    /// # Panics
    /// - Panics if the prime factors `p` or `q` are even or zero.
    fn dec(&mut self, c: &Self::C, sk: &Self::SK) -> Self::M {
        // CRT-based decryption
        let p_nz = NonZero::new(sk.p.resize::<MOD_LIMBS>()).unwrap();
        let q_nz = NonZero::new(sk.q.resize::<MOD_LIMBS>()).unwrap();

        let p_odd = Odd::new(sk.p.resize::<MOD_LIMBS>()).unwrap();
        let q_odd = Odd::new(sk.q.resize::<MOD_LIMBS>()).unwrap();
        let p_params = FixedMontyParams::new(p_odd);
        let q_params = FixedMontyParams::new(q_odd);

        let c_p = c.rem(&p_nz).resize::<PRIME_LIMBS>();
        let c_q = c.rem(&q_nz).resize::<PRIME_LIMBS>();

        // m1 = C^dp mod p
        let c_p_res = FixedMontyForm::new(&c_p.resize::<MOD_LIMBS>(), &p_params);
        let m1_wide = c_p_res.pow(&sk.d_p.resize::<MOD_LIMBS>()).retrieve();
        let m1 = m1_wide.resize::<PRIME_LIMBS>();

        // m2 = C^dq mod q
        let c_q_res = FixedMontyForm::new(&c_q.resize::<MOD_LIMBS>(), &q_params);
        let m2_wide = c_q_res.pow(&sk.d_q.resize::<MOD_LIMBS>()).retrieve();
        let m2 = m2_wide.resize::<PRIME_LIMBS>();

        // h = (m1 - m2) * q_inv mod p
        let m1_adjusted = if m1 < m2 { m1.wrapping_add(&sk.p) } else { m1 };
        let diff = m1_adjusted.wrapping_sub(&m2);

        let diff_res = FixedMontyForm::new(&diff.resize::<MOD_LIMBS>(), &p_params);
        let q_inv_res = FixedMontyForm::new(&sk.q_inv.resize::<MOD_LIMBS>(), &p_params);
        let h = (diff_res * q_inv_res).retrieve();

        // m = m2 + h * q
        let m_wide = h
            .resize::<MOD_LIMBS>()
            .wrapping_mul(&sk.q.resize::<MOD_LIMBS>());
        m_wide.wrapping_add(&m2.resize::<MOD_LIMBS>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pke::PKE;

    #[test]
    fn test_rsa_1024() {
        let mut rsa = RSA::<16, 8>::new();
        let (pk, sk) = rsa.r#gen();
        let mut bytes = [255u8; 128];
        bytes[0] = 0; // Ensure m < n
        let m = Uint::<16>::from_be_slice(&bytes);
        let c = rsa.enc(&m, &pk);
        let d = rsa.dec(&c, &sk);
        assert_eq!(m, d);
    }

    #[test]
    fn test_rsa_2048() {
        let mut rsa = RSA::<32, 16>::new();
        let (pk, sk) = rsa.r#gen();
        let mut bytes = [255u8; 256];
        bytes[0] = 0; // Ensure m < n
        let m = Uint::<32>::from_be_slice(&bytes);
        let c = rsa.enc(&m, &pk);
        let d = rsa.dec(&c, &sk);
        assert_eq!(m, d);
    }

    #[test]
    fn test_rsa_3072() {
        let mut rsa = RSA::<48, 24>::new();
        let (pk, sk) = rsa.r#gen();
        let mut bytes = [255u8; 384];
        bytes[0] = 0; // Ensure m < n
        let m = Uint::<48>::from_be_slice(&bytes);
        let c = rsa.enc(&m, &pk);
        let d = rsa.dec(&c, &sk);
        assert_eq!(m, d);
    }

    #[test]
    fn test_rsa_4096() {
        let mut rsa = RSA::<64, 32>::new();
        let (pk, sk) = rsa.r#gen();
        let mut bytes = [255u8; 512];
        bytes[0] = 0; // Ensure m < n
        let m = Uint::<64>::from_be_slice(&bytes);
        let c = rsa.enc(&m, &pk);
        let d = rsa.dec(&c, &sk);
        assert_eq!(m, d);
    }
}
