use crypto_bigint::Uint;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};

use crate::{
    groups::{MGParams, MGVal},
    helpers::random_mod_lb,
    pke::{AnamorphicPKE, PKE},
};

/// ElGamal encryption is defined over some group G
#[derive(Debug)]
pub struct ElGamal<const LIMBS: usize, G: MGParams<LIMBS>> {
    rng: ChaCha20Rng,
    params: std::marker::PhantomData<G>,
}

impl<const LIMBS: usize, G: MGParams<LIMBS>> ElGamal<LIMBS, G> {
    pub fn new() -> Self {
        Self::new_seeded(rand::rng().random())
    }

    pub fn new_seeded(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            params: std::marker::PhantomData,
        }
    }
}

impl<const LIMBS: usize, G: MGParams<LIMBS>> PKE for ElGamal<LIMBS, G> {
    type PK = MGVal<LIMBS, G>;

    type SK = Uint<LIMBS>;

    type M = MGVal<LIMBS, G>;

    type C = (MGVal<LIMBS, G>, MGVal<LIMBS, G>);

    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        // sk = 0 is bad, because then c1 = m
        let sk = random_mod_lb(&mut self.rng, Uint::ONE, G::q());
        // This won't panic, since g^q is by definition in the group
        let pk = MGVal::into_group(G::g().pow(&sk)).unwrap();

        (pk, sk)
    }

    fn enc(&mut self, m: Self::M, pk: Self::PK) -> Self::C {
        // Once again, we don't want r = 0, because then we have c1 = m
        let r = random_mod_lb(&mut self.rng, Uint::ONE, G::q());

        // This won't panic, since g^k * (g^a)^r = g^(k + a * r), which is in the group
        let c1 = MGVal::into_group(*m * pk.pow(&r)).unwrap();
        // This won't panic, since this is the definition of being in the group
        let c2 = MGVal::into_group(G::g().pow(&r)).unwrap();

        (c1, c2)
    }

    fn dec(&mut self, (c1, c2): Self::C, sk: Self::SK) -> Self::M {
        MGVal::into_group(*c1 * c2.pow(&sk).invert().unwrap()).unwrap()
    }
}

impl<const LIMBS: usize, G: MGParams<LIMBS>> AnamorphicPKE for ElGamal<LIMBS, G> {}
