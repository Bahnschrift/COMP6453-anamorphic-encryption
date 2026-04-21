use crypto_bigint::Uint;
use crypto_bigint::modular::ConstMontyForm;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};
use sha2::{Digest, Sha256};

use crate::helpers::bytes_to_bigint;
use crate::{groups::MCG, helpers::random_mod_lb, pke::PKE};

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

        let mut hasher = Sha256::new();
        hasher.update(u1.as_montgomery().to_le_bytes());
        hasher.update(u2.as_montgomery().to_le_bytes());
        hasher.update(v.as_montgomery().to_le_bytes());
        let h = bytes_to_bigint::<4>(&hasher.finalize()).expect("hash bigger than LIMBS");
        let h = h.resize::<LIMBS>();

        let w = G::from_modp(c.pow(&r) * d.pow(&(r.mul_mod(&h, &G::q())))).unwrap();

        ((v, w), (u1, u2))
    }

    fn dec(&mut self, c: &Self::C, sk: &Self::SK) -> Self::M {
        let ((v, w), (u1, u2)) = c;
        let (x1, x2, y1, y2, z) = sk;

        let mut hasher = Sha256::new();
        hasher.update(u1.as_montgomery().to_le_bytes());
        hasher.update(u2.as_montgomery().to_le_bytes());
        hasher.update(v.as_montgomery().to_le_bytes());
        let h = bytes_to_bigint::<4>(&hasher.finalize()).expect("hash bigger than LIMBS");
        let h = h.resize::<LIMBS>();

        let check = u1.pow(&(x1.add_mod(&y1.mul_mod(&h, &G::q()), &G::q())))
            * u2.pow(&(x2.add_mod(&y2.mul_mod(&h, &G::q()), &G::q())));

        if check == **w {
            G::from_modp(**v * u1.invert().unwrap().pow(z)).unwrap()
        } else {
            G::from_modp(ConstMontyForm::ONE).unwrap()
        }
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
