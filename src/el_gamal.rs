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
        let pk = G::into_group(G::g().pow(&sk)).unwrap();

        (pk, sk)
    }

    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C {
        // Once again, we don't want r = 0, because then we have c1 = m
        let r = random_mod_lb(&mut self.rng, Uint::ONE, G::q());

        // This won't panic, since g^k * (g^a)^r = g^(k + a * r), which is in the group
        let c1 = G::into_group(**m * pk.pow(&r)).unwrap();
        // This won't panic, since this is the definition of being in the group
        let c2 = G::into_group(G::g().pow(&r)).unwrap();

        (c1, c2)
    }

    fn dec(&mut self, (c1, c2): &Self::C, sk: &Self::SK) -> Self::M {
        G::into_group(**c1 * c2.pow(&sk).invert().unwrap()).unwrap()
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
    ) -> Option<<ElGamal<LIMBS, G> as PKE>::M> {
        todo!()
    }

    fn a_dec(&mut self, dk: &Self::DK, c: &<ElGamal<LIMBS, G> as PKE>::C) -> Option<Self::CM> {
        todo!()
    }
}
