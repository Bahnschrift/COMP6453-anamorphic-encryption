use std::collections::HashMap;

use crypto_bigint::Uint;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::{
    groups::MCG,
    helpers::random_mod_lb,
    pke::{AnamorphicPKE, PKE},
};

/// ElGamal encryption is defined over some group G
#[derive(Debug)]
pub struct ElGamal<const LIMBS: usize, G: MCG<LIMBS>> {
    rng: ChaCha20Rng,
    group: std::marker::PhantomData<G>,
}

impl<const LIMBS: usize, G: MCG<LIMBS>> ElGamal<LIMBS, G> {
    fn gen_seed() -> u64 {
        rand::rng().random()
    }

    pub fn new() -> Self {
        Self::new_seeded(Self::gen_seed())
    }

    pub fn new_seeded(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            group: std::marker::PhantomData,
        }
    }
}

impl<const LIMBS: usize, G: MCG<LIMBS>> PKE for ElGamal<LIMBS, G> {
    type PK = G;
    type SK = Uint<LIMBS>;
    type M = G;
    type C = (G, G);

    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        // sk = 0 is bad, because then c1 = m
        let sk = random_mod_lb(&mut self.rng, Uint::ONE, G::q());
        // This won't panic, since g^q is by definition in the group
        let pk = G::from_modp(G::g().pow(&sk)).unwrap();

        (pk, sk)
    }

    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C {
        // Once again, we don't want r = 0, because then we have c1 = m
        let r = random_mod_lb(&mut self.rng, Uint::ONE, G::q());

        // This won't panic, since g^k * (g^a)^r = g^(k + a * r), which is in the group
        let c1 = G::from_modp(**m * pk.pow(&r)).unwrap();
        // This won't panic, since this is the definition of being in the group
        let c2 = G::from_modp(G::g().pow(&r)).unwrap();

        (c1, c2)
    }

    fn dec(&mut self, (c1, c2): &Self::C, sk: &Self::SK) -> Self::M {
        G::from_modp(**c1 * c2.pow(&sk).invert().unwrap()).unwrap()
    }
}

/// Params used in AME.
/// We will not want these numbers to be too large or enc/dec will be painfully slow, u32 should be sufficient
#[derive(Debug)]
pub struct ElGamalAnam<const LIMBS: usize, G: MCG<LIMBS>> {
    el_gamal: ElGamal<LIMBS, G>,
    /// Covert message space size
    l: u32,
    /// Upper bound of randomly generated x, 0 < x < s.
    ///
    /// x adds randomness to the random offset(F(k, x, y)), there will be a possibility of 1/e we never get a matching feature without it.
    s: u32,

    /// Upper bound of randomly generated y, 0 < y < t.
    ///
    /// We will require d(2nd part of ciphertext) = d(g^(cm + F(k, x, y))) == y
    t: u32,
}

impl<const LIMBS: usize, G: MCG<LIMBS>> ElGamalAnam<LIMBS, G> {
    pub fn new(l: u32, s: u32, t: u32) -> Self {
        Self {
            el_gamal: ElGamal::new(),
            l,
            s,
            t,
        }
    }

    pub fn new_seeded(seed: u64, l: u32, s: u32, t: u32) -> Self {
        Self {
            el_gamal: ElGamal::new_seeded(seed),
            l,
            s,
            t,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ElGamalDK<const LIMBS: usize, CM>
where
    CM: Clone,
{
    /// The symmetric key used to encrypt and decrypt covert messages
    ///
    /// It act as a random noise in the generation of the offset.
    /// Without it, an adversary can easily recover the covert message by trying all possible x in [0, s).
    /// Also, it should not be too short to prevent brute-force.
    k: [u8; 32],

    /// A hashmap stores g^cm as key and cm as value
    ///
    /// Upon decryption, we recover y with d(c2), then we search the space of [0, s) to try each possible x.
    /// We can then compute offset = F(k, x, y), and check if c2 / g^offset = g^cm is in this table.
    /// If it is, then the x is correct, and we have found the covert message.
    ///
    /// It is not necessarily a secret, but a receiver will need to generate it again from the parameters if it is not delivered with the key
    t: HashMap<Uint<LIMBS>, CM>,
}

impl<const LIMBS: usize, G: MCG<LIMBS> + Clone + Send + Sync> ElGamalAnam<LIMBS, G> {
    /// Implementation of function d in the python version, extracts a feature from the 2nd part of the ciphertext.
    ///
    /// We simplified the approach by taking the lowest 32 bits from ciphertext and mod it by t, avoiding big int operations
    fn extract_feature(&self, c_2nd: &G) -> u32 {
        let val = c_2nd.retrieve();

        let bytes = val.to_le_bytes();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);

        let low_u32 = u32::from_le_bytes(buf);

        low_u32 % self.t
    }

    /// Implementation of function F in the python version, a hash function that takes in dk, x, y and outputs a random number in [0, q)
    ///
    /// We use it to generate a random offset, which is added to the covert message
    fn a_rng(
        &self,
        dk: &<Self as AnamorphicPKE<ElGamal<LIMBS, G>>>::DK,
        x: u32,
        y: u32,
    ) -> Uint<LIMBS> {
        let mut hasher = Sha256::new();
        hasher.update(&dk.k);
        hasher.update(&x.to_le_bytes());
        hasher.update(&y.to_le_bytes());

        let seed: [u8; 32] = hasher.finalize().into();

        let mut rng = ChaCha20Rng::from_seed(seed);

        random_mod_lb(&mut rng, Uint::ONE, G::q())
    }
}

impl<const LIMBS: usize, G: MCG<LIMBS> + Clone + Send + Sync> AnamorphicPKE<ElGamal<LIMBS, G>>
    for ElGamalAnam<LIMBS, G>
{
    type DK = ElGamalDK<LIMBS, Self::CM>;
    type CM = u32;

    /// Generate a double key to be used in anamorphic encryption and decryption.
    ///
    /// I did some benchmarking and this is actually the most time consuming part, taking 20x longer than encryption in debug mode
    fn a_gen(
        &mut self,
        _: &<ElGamal<LIMBS, G> as PKE>::SK,
        _: &<ElGamal<LIMBS, G> as PKE>::PK,
    ) -> Self::DK {
        // The symmetric key for anamorphic encryption
        let mut k = [0u8; 32];
        self.el_gamal.rng.fill(&mut k);

        // Precompute the table for looking up cm by g^cm during decryption
        let mut t = HashMap::new();
        let mut current_g = G::from_modp(crypto_bigint::modular::ConstMontyForm::ONE).unwrap();
        let base_g = G::g();

        for cm in 0..self.l {
            t.insert(current_g.retrieve(), cm);

            let next_val = current_g.mul(&base_g);
            current_g = G::from_modp(next_val).unwrap();
        }

        ElGamalDK { k, t }
    }

    // Encrypt a message along with a covert message cm.
    fn a_enc(
        &mut self,
        pk: &<ElGamal<LIMBS, G> as PKE>::PK,
        dk: &Self::DK,
        m: &<ElGamal<LIMBS, G> as PKE>::M,
        cm: &Self::CM,
    ) -> Option<<ElGamal<LIMBS, G> as PKE>::C> {
        if cm >= &self.l {
            return None;
        }

        // Find a valid pair of x and y and corresponding ciphertext using reject sampling
        // We used rayon to speed this up
        let result = (0..self.s)
            .into_par_iter()
            .flat_map(|x| (0..self.t).into_par_iter().map(move |y| (x, y)))
            .find_map_any(|(x, y)| {
                let t_offset = self.a_rng(dk, x, y);

                // Standard ElGamal
                let r = t_offset.add_mod(&Uint::from(*cm), &G::q());
                let c2 = G::from_modp(G::g().pow(&r)).unwrap();

                // Check if the ciphertext contains the covert message
                let feature = self.extract_feature(&c2);

                if feature == y {
                    let c1 = G::from_modp(**m * pk.pow(&r)).unwrap();
                    Some((c1, c2))
                } else {
                    None
                }
            });

        result
    }

    /// Decrypt a ciphertext with the double key, return the covert message.
    fn a_dec(&mut self, dk: &Self::DK, c: &<ElGamal<LIMBS, G> as PKE>::C) -> Option<Self::CM> {
        // Recover y from the ciphertext
        let y = self.extract_feature(&c.1);

        // Then try all possible x to find a match in the table, if we find one, return the corresponding cm
        let result = (0..self.s).into_par_iter().find_map_any(|x| {
            let t = self.a_rng(dk, x, y);
            let t_neg = G::q().wrapping_sub(&t);
            let s_val = c.1.mul(&G::g().pow(&t_neg)).retrieve();

            if dk.t.contains_key(&s_val) {
                Some(dk.t[&s_val])
            } else {
                None
            }
        });

        result
    }
}

#[cfg(test)]
mod tests_normal {
    use crate::{
        groups::{Group2048, Group4096, GroupSmall},
        helpers::{bigint_to_bytes, bytes_to_bigint},
    };

    use super::*;

    #[test]
    fn test_e2e_small() {
        // The small group can only hold ascii < 87
        let m = "!";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = GroupSmall::from_modq(mi).unwrap();

        let mut eg = ElGamal::new();
        let (pk, sk) = eg.r#gen();
        let (c1, c2) = eg.enc(&mg, &pk);
        let md = eg.dec(&(c1, c2), &sk);
        let dec = String::from_utf8(bigint_to_bytes(md.to_modq())).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    fn test_e2e_2048() {
        // Some bug with bigint_to_bytes means we can't use anything longer than this, even though we're definitely able to encode bigger strings
        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let mut eg = ElGamal::new();
        let (pk, sk) = eg.r#gen();

        let (c1, c2) = eg.enc(&mg, &pk);

        let md = eg.dec(&(c1, c2), &sk);
        let mdi = md.to_modq();
        let mdb = bigint_to_bytes(mdi);
        let dec = String::from_utf8(mdb).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    fn test_e2e_4096() {
        // Same bug here...
        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group4096::from_modq(mi).unwrap();

        let mut eg = ElGamal::new();
        let (pk, sk) = eg.r#gen();

        let (c1, c2) = eg.enc(&mg, &pk);

        let md = eg.dec(&(c1, c2), &sk);
        let mdi = md.to_modq();
        let mdb = bigint_to_bytes(mdi);
        let dec = String::from_utf8(mdb).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    /// 2046 bits or 255 full bytes available
    fn test_2048_msg_barely_fit() {
        let mut mb = [0b11111111u8; 256];
        mb[255] = 0b00111111;
        let mi = bytes_to_bigint(&mb).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let mut eg = ElGamal::new();
        let (pk, sk) = eg.r#gen();
        let (c1, c2) = eg.enc(&mg, &pk);

        let md = eg.dec(&(c1, c2), &sk);
        let mdi = md.to_modq();
        let mdb = bigint_to_bytes(mdi);

        assert_eq!(mb, mdb.as_slice());
    }
}

#[cfg(test)]
mod tests_anamorphic {
    use super::*;
    use crate::{
        groups::Group2048,
        helpers::{bigint_to_bytes, bytes_to_bigint},
    };

    #[test]
    fn test_2048_success() {
        let mut eg_anam = ElGamalAnam::new(256, 256, 256);
        let (pk, sk) = eg_anam.el_gamal.r#gen();
        let dk = eg_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let cm: u32 = 114;

        let c = eg_anam
            .a_enc(&pk, &dk, &mg, &cm)
            .expect("Failed to encrypt with covert message");

        let cm_dec = eg_anam
            .a_dec(&dk, &c)
            .expect("Failed to decrypt covert message");

        assert_eq!(cm, cm_dec);

        let m_dec = eg_anam.el_gamal.dec(&c, &sk);
        let mdi = m_dec.to_modq();
        let mdb = bigint_to_bytes(mdi);
        let dec = String::from_utf8(mdb).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    fn test_2048_out_of_range_cm() {
        // try to encrypt with a cm > l, should return None
        let mut eg_anam = ElGamalAnam::new(256, 256, 256);
        let (pk, sk) = eg_anam.el_gamal.r#gen();
        let dk = eg_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let cm: u32 = 300;

        let c = eg_anam.a_enc(&pk, &dk, &mg, &cm);

        assert!(c.is_none());
    }

    #[test]
    fn test_2048_normal_ciphertext() {
        // decrypt a normal ciphertext with the anamorphic decryption, should return None
        let mut eg_anam = ElGamalAnam::new(256, 256, 256);
        let (pk, sk) = eg_anam.el_gamal.r#gen();
        let dk = eg_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let c = eg_anam.el_gamal.enc(&mg, &pk);
        let cm_dec = eg_anam.a_dec(&dk, &c);
        assert!(cm_dec.is_none());
    }
}
