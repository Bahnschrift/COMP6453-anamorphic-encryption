use crypto_bigint::Uint;
use crypto_bigint::modular::ConstMontyForm;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use std::collections::HashMap;

use crate::helpers::bytes_to_bigint;
use crate::{
    groups::MCG,
    helpers::random_mod_lb,
    pke::{AnamorphicPKE, PKE},
};

type RandomSeed = [u8; 32];

/// Cramer-Shoup encryption is defined over some group G
#[derive(Debug)]
pub struct CramerShoup<const LIMBS: usize, G: MCG<LIMBS>> {
    rng: ChaCha20Rng,
    group: std::marker::PhantomData<G>,
}

impl<const LIMBS: usize, G: MCG<LIMBS>> CramerShoup<LIMBS, G> {
    fn gen_seed() -> RandomSeed {
        rand::rng().random()
    }

    pub fn new() -> Self {
        Self::new_seeded(Self::gen_seed())
    }

    pub fn new_seeded(seed: RandomSeed) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
            group: std::marker::PhantomData,
        }
    }

    fn hash(u1: &G, u2: &G, v: &G) -> Uint<LIMBS> {
        let mut hasher = Sha256::new();
        hasher.update(u1.as_montgomery().to_le_bytes());
        hasher.update(u2.as_montgomery().to_le_bytes());
        hasher.update(v.as_montgomery().to_le_bytes());
        let h = bytes_to_bigint::<4>(&hasher.finalize()).expect("hash bigger than LIMBS");
        let h = h.resize::<LIMBS>();

        h
    }
}

impl<const LIMBS: usize, G: MCG<LIMBS>> PKE for CramerShoup<LIMBS, G> {
    type PK = (G, G, G, G, G);
    type SK = (
        Uint<LIMBS>,
        Uint<LIMBS>,
        Uint<LIMBS>,
        Uint<LIMBS>,
        Uint<LIMBS>,
    );
    type M = G;
    type C = ((G, G), (G, G));

    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        let (ge1, ge2, x1, x2, y1, y2, z) = {
            let mut r = || random_mod_lb(&mut self.rng, Uint::ONE, G::q());
            (r(), r(), r(), r(), r(), r(), r())
        };

        let (g1, g2) = (
            G::from_modp(G::g().pow(&ge1)).unwrap(),
            G::from_modp(G::g().pow(&ge2)).unwrap(),
        );

        let c = G::from_modp(g1.pow(&x1) * g2.pow(&x2)).unwrap();
        let d = G::from_modp(g1.pow(&y1) * g2.pow(&y2)).unwrap();
        let e = G::from_modp(g1.pow(&z)).unwrap();

        let pk = (g1, g2, c, d, e);
        let sk = (x1, x2, y1, y2, z);

        (pk, sk)
    }

    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C {
        let (g1, g2, c, d, e) = pk;

        let r = random_mod_lb(&mut self.rng, Uint::ONE, G::q());

        let u1 = G::from_modp(g1.pow(&r)).unwrap();
        let u2 = G::from_modp(g2.pow(&r)).unwrap();

        let v = G::from_modp(**m * e.pow(&r)).unwrap();
        let h = Self::hash(&u1, &u2, &v);
        let w = G::from_modp(c.pow(&r) * d.pow(&(r.mul_mod(&h, &G::q())))).unwrap();

        let c = ((v, w), (u1, u2));

        c
    }

    fn dec(&mut self, c: &Self::C, sk: &Self::SK) -> Self::M {
        let ((v, w), (u1, u2)) = c;
        let (x1, x2, y1, y2, z) = sk;

        let h = Self::hash(&u1, &u2, &v);

        let check = u1.pow(&(x1.add_mod(&y1.mul_mod(&h, &G::q()), &G::q())))
            * u2.pow(&(x2.add_mod(&y2.mul_mod(&h, &G::q()), &G::q())));

        if check == **w {
            G::from_modp(**v * u1.invert().unwrap().pow(z)).unwrap()
        } else {
            // TODO: Use a different special symbol, or an option?
            G::from_modp(ConstMontyForm::ONE).unwrap()
        }
    }
}

/// Params used in AME.
/// We will not want these numbers to be too large or enc/dec will be painfully slow, u32 should be sufficient
#[derive(Debug)]
pub struct CramerShoupAnam<const LIMBS: usize, G: MCG<LIMBS>> {
    cramer_shoup: CramerShoup<LIMBS, G>,
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

impl<const LIMBS: usize, G: MCG<LIMBS>> CramerShoupAnam<LIMBS, G> {
    pub fn new(l: u32, s: u32, t: u32) -> Self {
        Self {
            cramer_shoup: CramerShoup::new(),
            l,
            s,
            t,
        }
    }

    pub fn new_seeded(seed: RandomSeed, l: u32, s: u32, t: u32) -> Self {
        Self {
            cramer_shoup: CramerShoup::new_seeded(seed),
            l,
            s,
            t,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CramerShoupDK<const LIMBS: usize, G: MCG<LIMBS>, CM>
where
    CM: Clone,
{
    pk: <CramerShoup<LIMBS, G> as PKE>::PK,

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

impl<const LIMBS: usize, G: MCG<LIMBS> + Clone + Send + Sync> CramerShoupAnam<LIMBS, G> {
    /// Implementation of function d in the python version, extracts a feature from the 2nd part of the ciphertext.
    ///
    /// We simplified the approach by taking the lowest 32 bits from ciphertext and mod it by t, avoiding big int operations
    fn extract_feature(&self, u1: &G) -> u32 {
        let val = u1.retrieve();

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
        dk: &<Self as AnamorphicPKE<CramerShoup<LIMBS, G>>>::DK,
        x: u32,
        y: u32,
    ) -> Uint<LIMBS> {
        let mut hasher = Sha256::new();
        hasher.update(&dk.k);
        hasher.update(&x.to_le_bytes());
        hasher.update(&y.to_le_bytes());

        let seed: RandomSeed = hasher.finalize().into();

        let mut rng = ChaCha20Rng::from_seed(seed);

        random_mod_lb(&mut rng, Uint::ONE, G::q())
    }
}

impl<const LIMBS: usize, G: MCG<LIMBS> + Clone + Send + Sync> AnamorphicPKE<CramerShoup<LIMBS, G>>
    for CramerShoupAnam<LIMBS, G>
{
    type DK = CramerShoupDK<LIMBS, G, Self::CM>;
    type CM = u32;

    /// Generate a double key to be used in anamorphic encryption and decryption.
    ///
    fn a_gen(
        &mut self,
        _: &<CramerShoup<LIMBS, G> as PKE>::SK,
        pk: &<CramerShoup<LIMBS, G> as PKE>::PK,
    ) -> Self::DK {
        let (g1, _, _, _, _) = pk;

        // The symmetric key for anamorphic encryption
        let mut k = [0u8; 32];
        self.cramer_shoup.rng.fill(&mut k);

        // Precompute the table for looking up cm by g^cm during decryption
        let mut t = HashMap::new();
        let mut current_g = G::from_modp(ConstMontyForm::ONE).unwrap();
        let base_g = g1;

        for cm in 0..self.l {
            t.insert(current_g.retrieve(), cm);

            let next_val = current_g.mul(base_g);
            current_g = G::from_modp(next_val).unwrap();
        }

        let pk = pk.clone();

        CramerShoupDK { pk, k, t }
    }

    // Encrypt a message along with a covert message cm.
    fn a_enc(
        &mut self,
        dk: &Self::DK,
        m: &<CramerShoup<LIMBS, G> as PKE>::M,
        cm: &Self::CM,
    ) -> Option<<CramerShoup<LIMBS, G> as PKE>::C> {
        let (g1, g2, c, d, e) = dk.pk.clone();

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

                // Standard Cramer-Shoup
                let r = t_offset.add_mod(&Uint::from(*cm), &G::q());

                let u1 = G::from_modp(g1.pow(&r)).unwrap();

                // Check if the ciphertext contains the covert message
                let feature = self.extract_feature(&u1);

                if feature != y {
                    return None;
                }

                let u2 = G::from_modp(g2.pow(&r)).unwrap();

                let v = G::from_modp(**m * e.pow(&r)).unwrap();
                let h = CramerShoup::hash(&u1, &u2, &v);
                let w = G::from_modp(c.pow(&r) * d.pow(&(r.mul_mod(&h, &G::q())))).unwrap();

                let c = ((v, w), (u1, u2));

                Some(c)
            });

        result
    }

    /// Decrypt a ciphertext with the double key, return the covert message.
    fn a_dec(&mut self, dk: &Self::DK, c: &<CramerShoup<LIMBS, G> as PKE>::C) -> Option<Self::CM> {
        let (g1, _, _, _, _) = dk.pk.clone();
        let (_, (u1, _)) = c;

        // Recover y from the ciphertext
        let y = self.extract_feature(&u1);

        // Then try all possible x to find a match in the table, if we find one, return the corresponding cm
        let result = (0..self.s).into_par_iter().find_map_any(|x| {
            let t = self.a_rng(dk, x, y);
            let t_neg = G::q().wrapping_sub(&t);
            let s_val = u1.mul(&g1.pow(&t_neg)).retrieve();

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

        let mut cs = CramerShoup::new();
        let (pk, sk) = cs.r#gen();
        let c = cs.enc(&mg, &pk);
        let md = cs.dec(&c, &sk);
        let dec = String::from_utf8(bigint_to_bytes(md.to_modq())).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    fn test_e2e_2048() {
        // Some bug with bigint_to_bytes means we can't use anything longer than this, even though we're definitely able to encode bigger strings
        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let mut cs = CramerShoup::new();
        let (pk, sk) = cs.r#gen();

        let c = cs.enc(&mg, &pk);

        let md = cs.dec(&c, &sk);
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

        let mut cs = CramerShoup::new();
        let (pk, sk) = cs.r#gen();

        let c = cs.enc(&mg, &pk);

        let md = cs.dec(&c, &sk);
        let mdi = md.to_modq();
        let mdb = bigint_to_bytes(mdi);
        let dec = String::from_utf8(mdb).unwrap();

        assert_eq!(m, dec);
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
        let mut cs_anam = CramerShoupAnam::new(256, 256, 256);
        let (pk, sk) = cs_anam.cramer_shoup.r#gen();
        let dk = cs_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let cm: u32 = 114;

        let c = cs_anam
            .a_enc(&dk, &mg, &cm)
            .expect("Failed to encrypt with covert message");

        let cm_dec = cs_anam
            .a_dec(&dk, &c)
            .expect("Failed to decrypt covert message");

        assert_eq!(cm, cm_dec);

        let m_dec = cs_anam.cramer_shoup.dec(&c, &sk);
        let mdi = m_dec.to_modq();
        let mdb = bigint_to_bytes(mdi);
        let dec = String::from_utf8(mdb).unwrap();

        assert_eq!(m, dec);
    }

    #[test]
    fn test_2048_out_of_range_cm() {
        // try to encrypt with a cm > l, should return None
        let mut cs_anam = CramerShoupAnam::new(256, 256, 256);
        let (pk, sk) = cs_anam.cramer_shoup.r#gen();
        let dk = cs_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let cm: u32 = 300;

        let c = cs_anam.a_enc(&dk, &mg, &cm);

        assert!(c.is_none());
    }

    #[test]
    fn test_2048_normal_ciphertext() {
        // decrypt a normal ciphertext with the anamorphic decryption, should return None
        let mut cs_anam = CramerShoupAnam::new(256, 256, 256);
        let (pk, sk) = cs_anam.cramer_shoup.r#gen();
        let dk = cs_anam.a_gen(&sk, &pk);

        let m = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible.";
        let mi = bytes_to_bigint(m.as_bytes()).unwrap();
        let mg = Group2048::from_modq(mi).unwrap();

        let c = cs_anam.cramer_shoup.enc(&mg, &pk);
        let cm_dec = cs_anam.a_dec(&dk, &c);
        assert!(cm_dec.is_none());
    }
}
