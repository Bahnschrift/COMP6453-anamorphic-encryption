use std::ops::Mul;
use std::ops::Sub;

use crypto_bigint::modular::FixedMontyForm;
use crypto_bigint::modular::FixedMontyParams;
use crypto_bigint::{NonZero, Odd, Uint};
use crypto_primes::{Flavor, random_prime};
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};

use crate::pke::PKE;

type RandomSeed = [u8; 32];

/// RSA public key
pub struct RsaPK<const MOD_LIMBS: usize> {
    /// Modulus
    n: Uint<MOD_LIMBS>,
    /// Public exponent, we will use 65537 for this
    e: Uint<1>,
}

/// RSA private key, fields are from the second private key representation given by RFC8017, section 3.2
/// We use snake case for some fields since this is in Rust
pub struct RsaSK<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    /// The first factor
    p: Uint<PRIME_LIMBS>,
    /// The second factor
    q: Uint<PRIME_LIMBS>,
    /// CRT exponent of p, d mod (p - 1)
    d_p: Uint<PRIME_LIMBS>,
    /// CRT exponent of q, d mod (q - 1)
    d_q: Uint<PRIME_LIMBS>,
    /// CRT coefficient, q^-1 mod p
    q_inv: Uint<PRIME_LIMBS>,
    // We don't intend to implement multi-prime RSA, so the triplets are not included
}

/// Standard RSA implementation
pub struct RSA<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    rng: ChaCha20Rng,
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> RSA<MOD_LIMBS, PRIME_LIMBS> {
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(rand::rng().random()),
        }
    }

    pub fn new_seeded(seed: RandomSeed) -> Self {
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

    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        // We will just hardcode e like everyone else does
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
            // since e is prime and we ensured p and q are not factors of e
            let d = e.resize().invert_mod(&phi_n_nz).unwrap();

            // dP = d mod (p - 1)
            let d_p = d.rem(&p_minus_1);

            // dQ = d mod (q - 1)
            let d_q = d.rem(&q_minus_1);

            // qInv = q^-1 mod p
            // p > q, should be safe
            let p_nz = NonZero::new(p).unwrap();
            // q and p should be coprime so this should also be safe
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

    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C {
        // C = M^e mod N
        let mod_odd = Odd::new(pk.n).unwrap();
        let params = FixedMontyParams::new(mod_odd);

        let m_res = FixedMontyForm::new(m, &params);
        let e_mod = pk.e.resize::<MOD_LIMBS>();

        m_res.pow(&e_mod).retrieve()
    }

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
    fn test_rsa_2048() {
        let mut rsa = RSA::<32, 16>::new();

        let (pk, sk) = rsa.r#gen();

        let m = Uint::<32>::from(12345u32);
        let c = rsa.enc(&m, &pk);
        let d = rsa.dec(&c, &sk);

        assert_eq!(m, d);
    }
}
