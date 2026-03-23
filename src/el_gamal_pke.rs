// This follows construction 5 from the paper

use crypto_bigint::{
    NonZero, RandomMod, Uint,
    modular::{ConstMontyForm, ConstMontyParams},
};
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};

// Packaging these into a module so I can just collapse them in my editor
#[allow(dead_code)] // Disables warnings just for the consts module
mod consts {
    pub(super) const PTINY_STR: &str = "0000000000000017"; // 23
    pub(super) const QTINY_STR: &str = "000000000000000B"; // 11
    pub(super) const GTINY: u8 = 2;

    // A collection of very large primes p, generators g, and the order of each generator q, which is also a prime.
    // These are taken from the appendix of RFC 7919

    // pub(super) means only the parent module can access these values.
    pub(super) const P2048_STR: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

    pub(super) const Q2048_STR: &str = "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF";

    pub(super) const G2048: u8 = 2;

    pub(super) const P3072_STR: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";

    pub(super) const Q3072_STR: &str = "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF79E0D90771FEACEBE12F20E95B363171BFFFFFFFFFFFFFFFF";

    pub(super) const G3072: u8 = 2;

    pub(super) const P4096_STR: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF";

    pub(super) const Q4096_STR: &str = "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF79E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7DBC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A00243FAADD2BF18E63D389AE44377DA18C576B50F0096CF34195483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7C764DAAD3FC45235A6DAD428FA20C170E345003F2F32AFB57FFFFFFFFFFFFFFF";

    pub(super) const G4096: u8 = 2;
}

// There's quite a lot to unpack here...
//
// The crate we're using, crypto_bigint, gives us a bunch of types for storing very large integers (U256, U512, etc.).
// These are all just type aliases for the generic type Uint<LIMBS>, where LIMBS is the size of some internal array.
// The value of limbs for different types can be different on different platforms, but let's just assume x86-64 for now.
// We define our struct here in terms of LIMBS because we want it to be able to work with any Uint size, so we can pick different sized primes.
// We could also just a very large size for all models that could fit any prime we want, but that would be bad for performance.
//
// crypto_bigint also provides us another type called ConstMontyForm<MOD, LIMBS> which is used for representing integers for modular arithmetic.
// Here, LIMBS is again related to how we store the numbers, but MOD is a special type created by calling const_monty_params! macro.
// MOD defines the modulus for the number system we're working in.
#[derive(Debug)]
pub struct ElGamalPKE<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    rng: ChaCha20Rng,
    q: NonZero<Uint<LIMBS>>,
    g: ConstMontyForm<MOD, LIMBS>,
}

// A helper macro for defining preset prime / generator / order tuples
macro_rules! el_gamal_impl {
    ($t:ident, $modt:ident, $newfn:ident, $limbs:expr, $pstr:expr, $qstr: expr, $g:expr $(,)?) => {
        crypto_bigint::const_prime_monty_params!($modt, crypto_bigint::Uint<$limbs>, $pstr, $g);
        pub type $t = ElGamalPKE<$limbs, $modt>;

        impl $t {
            pub fn $newfn() -> Self {
                Self::new(
                    NonZero::<Uint<$limbs>>::new_unwrap(Uint::<$limbs>::from_be_hex($qstr)),
                    Uint::<$limbs>::from_u64($g),
                )
            }
        }
    };
}

el_gamal_impl!(
    ElGamalTiny,
    ModPTiny,
    new_tiny,
    1,
    consts::PTINY_STR,
    consts::QTINY_STR,
    2
);
el_gamal_impl!(
    ElGamal2048,
    ModP2048,
    new_2048,
    32,
    consts::P2048_STR,
    consts::Q2048_STR,
    2
);
el_gamal_impl!(
    ElGamal3072,
    ModP3072,
    new_3072,
    48,
    consts::P3072_STR,
    consts::Q3072_STR,
    2
);
el_gamal_impl!(
    ElGamal4096,
    ModP4096,
    new_4096,
    64,
    consts::P4096_STR,
    consts::Q4096_STR,
    2
);

impl<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> ElGamalPKE<LIMBS, MOD> {
    /// When calling, you must ensure that:
    /// - order(g) = q (working with integers modulo p)
    /// - p, defined as the modulus in M, is a prime
    /// - q is a prime
    // NOTE: could potentially mark this as unsafe?
    // It can't cause any memory safety issues, but stuff might not work if these preconditions aren't met.
    pub fn new(q: NonZero<Uint<LIMBS>>, g: Uint<LIMBS>) -> Self {
        // I'm unsure about the security of using a non-cryptographically secure generator like this for the seed.
        Self::new_seeded(q, g, rand::rng().random())
    }

    pub fn new_seeded(q: NonZero<Uint<LIMBS>>, g: Uint<LIMBS>, seed: u64) -> Self {
        Self {
            // ChaCha20 is theoretically cryptographically secure.
            rng: ChaCha20Rng::seed_from_u64(seed),
            q,
            g: ConstMontyForm::<MOD, LIMBS>::new(&g),
        }
    }

    /// Returns the modulus of the integers we are working with
    pub fn p() -> Uint<LIMBS> {
        *MOD::PARAMS.modulus().as_ref()
    }

    /// Generates the `(pk, sk)` tuple.
    // gen is a reserved keyword in rust. We bypass this by using the r# syntax.
    //
    // Note that we need &mut self here instead of just &self because using self.rng requires
    // mutating self.rng.
    pub fn r#gen(&mut self) -> (Uint<LIMBS>, Uint<LIMBS>) {
        // sk = uniformly random integer 1 <= k < q
        // We subtract 1 for the modulus then add 1 after to prevent generating 0.
        // This is important because a secret key of zero would result in a public key of 1,
        // which would just reveal every message in c1.
        let sk = Uint::<LIMBS>::random_mod_vartime(
            &mut self.rng,
            &NonZero::<Uint<LIMBS>>::new(*self.q - Uint::<LIMBS>::ONE).expect("Should have q > 1."),
        ) + Uint::<LIMBS>::ONE;

        // pk = g^sk
        let pk = self.g.pow(&sk);

        // output (sk, pk)
        (sk, pk.retrieve())
    }

    /// Uses the public key `pk` to encode message `m`.
    /// Returns `None` if `m` is not in the message space, which is the cyclic group generated by `g` modulo `p`.
    pub fn enc(&mut self, pk: Uint<LIMBS>, m: Uint<LIMBS>) -> Option<(Uint<LIMBS>, Uint<LIMBS>)> {
        if m == Uint::<LIMBS>::ZERO || m >= Self::p() {
            // Message outside of message space.
            return None;
        }

        let m = ConstMontyForm::<MOD, LIMBS>::new(&m);
        if m.pow(&self.q) != ConstMontyForm::<MOD, LIMBS>::ONE {
            // Message not in subgroup generated by g
            return None;
        }

        let pk = ConstMontyForm::<MOD, LIMBS>::new(&pk);

        let r = Uint::<LIMBS>::random_mod_vartime(&mut self.rng, &self.q);
        let c1 = m * pk.pow(&r);
        let c2 = self.g.pow(&r);

        Some((c1.retrieve(), c2.retrieve()))
    }

    /// Uses the secret key `sk` to decode some ciphertext `(c1, c2)`.
    // Need to find some way to get the modulo multiplicative inverse
    pub fn dec(&self, sk: Uint<LIMBS>, (c1, c2): (Uint<LIMBS>, Uint<LIMBS>)) -> Uint<LIMBS> {
        let c1 = ConstMontyForm::<MOD, LIMBS>::new(&c1);
        let c2 = ConstMontyForm::<MOD, LIMBS>::new(&c2);
        (c1 * c2.pow(&sk).invert().expect("Failed to invert")).retrieve()
    }
}

// Test functions in here can be run automatically with `cargo test`.
#[cfg(test)]
mod test {
    use crypto_bigint::{U64, U2048, U3072, U4096};

    use crate::el_gamal_pke::{
        ElGamalPKE,
        consts::{P2048_STR, P3072_STR, P4096_STR, Q2048_STR, Q3072_STR, Q4096_STR},
    };

    #[test]
    fn verify_q_2048() {
        assert_eq!(
            U2048::from_be_hex(Q2048_STR),
            (U2048::from_be_hex(P2048_STR) - U2048::ONE) / U2048::from_u8(2)
        );
    }

    #[test]
    fn verify_q_3072() {
        assert_eq!(
            U3072::from_be_hex(Q3072_STR),
            (U3072::from_be_hex(P3072_STR) - U3072::ONE) / U3072::from_u8(2)
        );
    }

    #[test]
    fn verify_q_4096() {
        assert_eq!(
            U4096::from_be_hex(Q4096_STR),
            (U4096::from_be_hex(P4096_STR) - U4096::ONE) / U4096::from_u8(2)
        );
    }

    #[test]
    fn enc_dec_2048_valid_1() {
        let mut pke = ElGamalPKE::new_2048();
        let (sk, pk) = pke.r#gen();

        let m = U2048::from_u8(5);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }
    #[test]
    fn enc_dec_2048_valid_2() {
        let mut pke = ElGamalPKE::new_2048();
        let (sk, pk) = pke.r#gen();

        let m = U2048::from_u8(2);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }

    #[test]
    fn enc_dec_2048_valid_3() {
        let mut pke = ElGamalPKE::new_2048();
        let (sk, pk) = pke.r#gen();

        let m = U2048::from_u64(129836918726312);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }

    #[test]
    fn enc_dec_4096_valid_1() {
        let mut pke = ElGamalPKE::new_4096();
        let (sk, pk) = pke.r#gen();

        let m = U4096::from_u8(5);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }

    #[test]
    fn enc_dec_4096_valid_2() {
        let mut pke = ElGamalPKE::new_4096();
        let (sk, pk) = pke.r#gen();

        let m = U4096::from_u8(2);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }

    #[test]
    fn enc_dec_4096_valid_3() {
        let mut pke = ElGamalPKE::new_4096();
        let (sk, pk) = pke.r#gen();

        let m = U4096::from_u64(129836918726312);
        let (c1, c2) = pke.enc(pk, m).expect("m should be in subgroup");

        let m_dec = pke.dec(sk, (c1, c2));
        assert_eq!(m, m_dec);
    }

    const SMALL_PKE_MESSAGE_SPACE: [u8; 11] = [1, 2, 3, 4, 6, 8, 9, 12, 13, 16, 18];

    // Validates that all appropriate messages are accepted / rejected.
    #[test]
    fn test_small() {
        let mut pke = ElGamalPKE::new_tiny();

        let (sk, pk) = pke.r#gen();

        for i in 0..=23 {
            let m = U64::from_u8(i);

            let c = pke.enc(pk, m);
            if !SMALL_PKE_MESSAGE_SPACE.contains(&i) {
                assert_eq!(c, None);
            } else {
                let m_dec = pke.dec(sk, c.expect("m should be in subgroup"));
                assert_eq!(m, m_dec);
            }
        }
    }
}
