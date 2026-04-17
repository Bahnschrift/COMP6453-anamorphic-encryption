use std::collections::HashMap;

use crypto_bigint::Uint;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};

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

/// Params used in AME
/// We will not want these numbers to be too large or enc/dec will be painfully slow, u32 should be sufficient
#[derive(Debug)]
pub struct ElGamalAnam<const LIMBS: usize, G: MCG<LIMBS>> {
    el_gamal: ElGamal<LIMBS, G>,
    l: u32,
    s: u32,
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
    // Symmetric key - 32 bytes
    k: [u8; 32],

    /// Discrete log lookup table
    t: HashMap<Uint<LIMBS>, CM>,
}

impl<const LIMBS: usize, G: MCG<LIMBS> + Clone> AnamorphicPKE<ElGamal<LIMBS, G>>
    for ElGamalAnam<LIMBS, G>
{
    type DK = ElGamalDK<LIMBS, Self::CM>;
    type CM = u32;

    fn a_gen(
        &mut self,
        _: &<ElGamal<LIMBS, G> as PKE>::SK,
        _: &<ElGamal<LIMBS, G> as PKE>::PK,
    ) -> Self::DK {
        // The anamorphic symmetric key, 32 random bytes
        let mut k = [0u8; 32];
        self.el_gamal.rng.fill(&mut k);

        // The lookup table for the receiver to check if they have found the correct y
        let mut t = HashMap::new();
        let mut g = G::g();
        for cm in 0..self.l {
            t.insert(g.retrieve(), cm);
            g = g.mul(&G::g());
        }

        ElGamalDK { k, t }
    }

    fn a_enc(
        &mut self,
        dk: &Self::DK,
        m: &<ElGamal<LIMBS, G> as PKE>::M,
        cm: &Self::CM,
    ) -> Option<<ElGamal<LIMBS, G> as PKE>::C> {
        todo!()
    }

    fn a_dec(&mut self, dk: &Self::DK, c: &<ElGamal<LIMBS, G> as PKE>::C) -> Option<Self::CM> {
        todo!()
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
}

// #[cfg(test)]
// mod tests_anamorphic {
//     use super::*;
// }
