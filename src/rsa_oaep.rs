//! # RSA-OAEP PKE
//!
//! This module contains an implementation of the RSA Optimal Asymmetric Encryption Padding (OAEP)
//! public key encryption scheme as described in RFC 8017 Section 7.1.
//!
//! It supports both normal ([`RsaOaep`]) and anamorphic ([`RsaOaepAnam`]) modes.
//! The anamorphic mode allows embedding covert messages within the randomness of the OAEP padding.

use crate::pke::{AnamorphicPKE, PKE};
use crate::rsa::{RSA, RsaPK, RsaSK};
use crypto_bigint::Uint;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};
use sha2::digest::{Digest, FixedOutputReset};
use std::marker::PhantomData;
use std::ops::Deref;

type RandomSeed = [u8; 32];

/// Mask Generation Function 1
///
/// # Panics
/// - Panics if `mask_len` is too large for the chosen hash function (`maskLen > 2^32 * hLen`).
fn mgf1<H: Digest + FixedOutputReset>(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let h_len = <H as Digest>::output_size();

    if mask_len as u64 > (1u64 << 32) * h_len as u64 {
        panic!("mask too long");
    }

    let mut mask = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while mask.len() < mask_len {
        let mut hasher = H::new();
        Digest::update(&mut hasher, seed);
        Digest::update(&mut hasher, &counter.to_be_bytes());
        let hash = hasher.finalize();
        mask.extend_from_slice(&hash);
        counter += 1;
    }
    mask.truncate(mask_len);

    mask
}

/// Message and label of RSA-OAEP.
/// We place them together here to satisfy the PKE trait.
pub struct RsaOaepMsg {
    /// The message to be encrypted.
    pub m: Vec<u8>,
    /// Optional label.
    pub l: Vec<u8>,
}

/// RSA-OAEP ciphertext and label
pub struct RsaOaepCiphertext<const MOD_LIMBS: usize> {
    c: Uint<MOD_LIMBS>,
    l: Vec<u8>,
}

/// RSA-OAEP or RSAES-OAEP in RFC 8017 Section 7.1, based on the regular RSA PKE scheme.
///
/// OAEP padding provides a higher level of security than standard RSA padding by introducing
/// randomness and using a mask generation function (MGF1), making it resistant to certain
/// chosen-ciphertext attacks. This also allows us to implement an anamorphic encryption scheme
/// over it.
///
/// # Example usage
/// ```
/// use sha2::Sha256;
/// use anamorphic_encryption::pke::PKE;
/// use anamorphic_encryption::rsa_oaep::{RsaOaep, RsaOaepMsg};
///
/// // Create RSA-2048 with SHA-256
/// let mut rsa_oaep = RsaOaep::<32, 16, Sha256>::new();
/// let (pk, sk) = rsa_oaep.r#gen();
///
/// let msg = RsaOaepMsg {
///     m: b"message".to_vec(),
///     l: b"".to_vec(),
/// };
///
/// let c = rsa_oaep.enc(&msg, &pk);
/// let d = rsa_oaep.dec(&c, &sk);
/// assert_eq!(msg.m, d.m);
/// ```
pub struct RsaOaep<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset> {
    rsa: RSA<MOD_LIMBS, PRIME_LIMBS>,
    rng: ChaCha20Rng,
    _hasher: PhantomData<H>,
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset>
    RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>
{
    /// Creates a new randomly seeded `RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>`.
    pub fn new() -> Self {
        Self {
            rsa: RSA::new(),
            rng: ChaCha20Rng::from_seed(rand::rng().random()),
            _hasher: PhantomData,
        }
    }

    /// Creates a new `RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>` using the provided seed.
    pub fn new_seeded(seed: RandomSeed) -> Self {
        Self {
            rsa: RSA::new_seeded(seed),
            rng: ChaCha20Rng::from_seed(seed),
            _hasher: PhantomData,
        }
    }

    /// Encryption with a given seed, can be reused in anamorphic encryption
    ///
    /// # Panics
    /// - If the label `l` is longer than 2^61 - 1 bytes.
    /// - If the `seed` length does not match the hash output size.
    /// - If the message `m` is too long to fit in the OAEP padding.
    pub(crate) fn enc_with_seed(
        &mut self,
        RsaOaepMsg { m, l }: &RsaOaepMsg,
        pk: &RsaPK<MOD_LIMBS>,
        seed: &[u8],
    ) -> RsaOaepCiphertext<MOD_LIMBS> {
        // We follow the steps given in RFC 8017 Section 7.1.1

        // Length checking
        let k = Uint::<MOD_LIMBS>::BYTES;
        let h_len = <H as Digest>::output_size();

        // Ensure label is not too long for SHA-1
        if l.len() as u64 > (1u64 << 61) - 1 {
            panic!("label too long");
        }

        if seed.len() != h_len {
            panic!("invalid seed length");
        }

        // Check message length
        if k < 2 * h_len + 2 || m.len() > k - 2 * h_len - 2 {
            panic!("message too long");
        }

        // EME-OAEP encoding
        // Hash the label L
        let mut hasher = H::new();
        Digest::update(&mut hasher, l);
        let l_hash = hasher.finalize();

        let ps_len = k - m.len() - 2 * h_len - 2;
        let ps = vec![0u8; ps_len];

        // Construct data block DB
        // DB = lHash || PS || 0x01 || M
        let mut db = Vec::with_capacity(k - h_len - 1);
        db.extend_from_slice(&l_hash);
        db.extend_from_slice(&ps);
        db.push(0x01);
        db.extend_from_slice(m);

        let db_mask = mgf1::<H>(seed, k - h_len - 1);
        let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

        // masked_seed = seed xor seed_mask
        let seed_mask = mgf1::<H>(&masked_db, h_len);
        let masked_seed: Vec<u8> = seed
            .iter()
            .zip(seed_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Construct encoded message EM
        // EM = 0x00 || maskedSeed || maskedDB
        let mut em = vec![0x00];
        em.extend_from_slice(&masked_seed);
        em.extend_from_slice(&masked_db);

        // RSA encryption
        let em_int = Uint::<MOD_LIMBS>::from_be_slice(&em);

        // Encrypt with standard RSA scheme
        RsaOaepCiphertext {
            c: self.rsa.enc(&em_int, pk),
            l: l.clone(),
        }
    }

    /// Decryption, also recovering the seed, can be reused in anamorphic encryption
    ///
    /// # Panics
    /// - If the label `l` is longer than 2^61 - 1 bytes.
    /// - If the RSA modulus bit-width is insufficient for the chosen hash.
    /// - If decryption or padding validation fails.
    pub(crate) fn dec_recover_seed(
        &mut self,
        RsaOaepCiphertext { c, l }: &RsaOaepCiphertext<MOD_LIMBS>,
        sk: &RsaSK<MOD_LIMBS, PRIME_LIMBS>,
    ) -> (RsaOaepMsg, Vec<u8>) {
        let k = Uint::<MOD_LIMBS>::BYTES;
        let h_len = <H as Digest>::output_size();

        // About 2000 PB, but since the RFC required this check...
        if l.len() as u64 > (1u64 << 61) - 1 {
            panic!("decryption error");
        }

        if k < 2 * h_len + 2 {
            panic!("decryption error");
        }

        // Recover EM
        let em = self.rsa.dec(c, sk).to_be_bytes();

        // Check for Zero prefix
        if em[0] != 0x00 {
            panic!("decryption error");
        }

        // EME-OAEP decoding
        let mut hasher = H::new();
        Digest::update(&mut hasher, l);
        let l_hash = hasher.finalize();

        // Extract components
        let masked_seed = &em[1..1 + h_len];
        let masked_db = &em[1 + h_len..];

        // Unmask seed
        let seed_mask = mgf1::<H>(masked_db, h_len);
        let seed: Vec<u8> = masked_seed
            .iter()
            .zip(seed_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Unmask DB
        let db_mask = mgf1::<H>(&seed, k - h_len - 1);
        let db: Vec<u8> = masked_db
            .iter()
            .zip(db_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Validate lHash
        let expected_l_hash = &db[0..h_len];
        if l_hash[..] != expected_l_hash[..] {
            panic!("decryption error");
        }

        // Find exactly where the PS zeroes end and the 0x01 separator starts
        let mut separator_idx = h_len;
        while separator_idx < db.len() && db[separator_idx] == 0x00 {
            separator_idx += 1;
        }

        // Ensure separator exists and is 0x01
        if separator_idx == db.len() || db[separator_idx] != 0x01 {
            panic!("decryption error");
        }

        // Extract original message M
        (
            RsaOaepMsg {
                m: db[separator_idx + 1..].to_vec(),
                l: l.clone(),
            },
            seed,
        )
    }
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset> PKE
    for RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>
{
    type PK = RsaPK<MOD_LIMBS>;
    type SK = RsaSK<MOD_LIMBS, PRIME_LIMBS>;
    type M = RsaOaepMsg;
    type C = RsaOaepCiphertext<MOD_LIMBS>;

    /// Generate a standard RSA key pair, OAEP doesn't change key generation
    fn r#gen(&mut self) -> (Self::PK, Self::SK) {
        self.rsa.r#gen()
    }

    /// RSA-OAEP encryption, adds OAEP padding to the message and encrypts it with standard RSA
    ///
    /// # Panics:
    /// - If the message is too long to fit in the OAEP padding scheme (|m| > k - 2 * |hash| - 2)
    fn enc(&mut self, m_struct: &Self::M, pk: &Self::PK) -> Self::C {
        let mut seed = vec![0u8; <H as Digest>::output_size()];
        self.rng.fill(&mut seed[..]);
        self.enc_with_seed(m_struct, pk, &seed)
    }

    /// RSA-OAEP decryption, decrypts with standard RSA and then removes OAEP padding to recover the message
    ///
    /// # Panics:
    /// - If the OAEP padding is invalid
    fn dec(&mut self, c: &Self::C, sk: &Self::SK) -> Self::M {
        let (m, _seed) = self.dec_recover_seed(c, sk);
        m
    }
}

/// Double key for Anamorphic RSA-OAEP
pub struct RsaOaepDK<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    pub pk: RsaPK<MOD_LIMBS>,
    pub sk: RsaSK<MOD_LIMBS, PRIME_LIMBS>,
    pub k: Vec<u8>,
    /// Counter required for synchronized anamorphic scheme.
    // We use AtomicU64 for it so we can change it without making dk mutable.
    pub ctr: std::sync::atomic::AtomicU64,
}

/// Anamorphic RSA-OAEP scheme as described in Section 5.3 of the paper.
///
/// This is a synchronized anamorphic scheme that is much more efficient than the Anamorphic
/// ElGamal or Cramer-Shoup scheme in our implementation because it does not require rejection
/// sampling. The covert message length is determined by the output size of the chosen hash
/// function (e.g. 20 bytes for SHA-1) so it does not contain a `l` parameter.
///
/// # Example usage
/// ```
/// use sha2::Sha256;
/// use std::sync::atomic::AtomicU64;
/// use anamorphic_encryption::pke::{PKE, AnamorphicPKE};
/// use anamorphic_encryption::rsa_oaep::{RsaOaepAnam, RsaOaepMsg, RsaOaepDK};
///
/// let mut rsa_anam = RsaOaepAnam::<32, 16, Sha256>::new();
/// let (pk, sk) = rsa_anam.rsa_oaep.r#gen();
///
/// // Generate the double key
/// let dk = rsa_anam.a_gen(&sk, &pk);
///
/// // Embed a covert message
/// let msg = RsaOaepMsg {
///     m: b"message".to_vec(),
///     l: b"".to_vec(),
/// };
/// let cm = vec![18u8; 32];
///
/// let c = rsa_anam.a_enc(&dk, &msg, &cm).unwrap();
///
/// // Normal decryption
/// let d_normal = rsa_anam.rsa_oaep.dec(&c, &sk);
/// assert_eq!(d_normal.m, msg.m);
///
/// // Anamorphic decryption
/// // Using a fresh DK for decryption as this is a synchronized anamorphic scheme
/// let dk_recv = RsaOaepDK {
///     sk: sk.clone(),
///     pk: pk.clone(),
///     k: dk.k.clone(),
///     ctr: AtomicU64::new(0),
/// };
/// let cm_rec = rsa_anam.a_dec(&dk_recv, &c).unwrap();
/// assert_eq!(cm_rec, cm);
/// ```
pub struct RsaOaepAnam<
    const MOD_LIMBS: usize,
    const PRIME_LIMBS: usize,
    H: Digest + FixedOutputReset,
> {
    pub rsa_oaep: RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>,
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset> Deref
    for RsaOaepAnam<MOD_LIMBS, PRIME_LIMBS, H>
{
    type Target = RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>;

    fn deref(&self) -> &Self::Target {
        &self.rsa_oaep
    }
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset>
    RsaOaepAnam<MOD_LIMBS, PRIME_LIMBS, H>
{
    pub fn new() -> Self {
        Self {
            rsa_oaep: RsaOaep::new(),
        }
    }

    pub fn new_seeded(seed: RandomSeed) -> Self {
        Self {
            rsa_oaep: RsaOaep::new_seeded(seed),
        }
    }
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize, H: Digest + FixedOutputReset>
    AnamorphicPKE<RsaOaep<MOD_LIMBS, PRIME_LIMBS, H>> for RsaOaepAnam<MOD_LIMBS, PRIME_LIMBS, H>
{
    type DK = RsaOaepDK<MOD_LIMBS, PRIME_LIMBS>;
    type CM = Vec<u8>;

    fn a_gen(&mut self, sk: &RsaSK<MOD_LIMBS, PRIME_LIMBS>, pk: &RsaPK<MOD_LIMBS>) -> Self::DK {
        let mut k = vec![0u8; <H as Digest>::output_size()];
        self.rsa_oaep.rng.fill(&mut k[..]);

        RsaOaepDK {
            sk: sk.clone(),
            pk: pk.clone(),
            k,
            ctr: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn a_enc(
        &mut self,
        dk: &Self::DK,
        m: &RsaOaepMsg,
        cm: &Self::CM,
    ) -> Option<RsaOaepCiphertext<MOD_LIMBS>> {
        let h_len = <H as Digest>::output_size();
        if cm.len() != h_len {
            return None;
        }

        let ctr = dk.ctr.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut hasher = H::new();
        Digest::update(&mut hasher, &dk.k);
        Digest::update(&mut hasher, &ctr.to_be_bytes());
        let t = hasher.finalize();

        let mut seed = vec![0u8; h_len];
        for i in 0..h_len {
            seed[i] = cm[i] ^ t[i];
        }

        Some(self.rsa_oaep.enc_with_seed(m, &dk.pk, &seed))
    }

    fn a_dec(&mut self, dk: &Self::DK, c: &RsaOaepCiphertext<MOD_LIMBS>) -> Option<Self::CM> {
        let h_len = <H as Digest>::output_size();
        let (_m, seed) = self.rsa_oaep.dec_recover_seed(c, &dk.sk);

        let ctr = dk.ctr.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut hasher = H::new();
        Digest::update(&mut hasher, &dk.k);
        Digest::update(&mut hasher, &ctr.to_be_bytes());
        let t = hasher.finalize();

        let mut cm = vec![0u8; h_len];
        for i in 0..h_len {
            cm[i] = seed[i] ^ t[i];
        }

        Some(cm)
    }
}

#[cfg(test)]
mod tests_normal {
    use super::*;
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    #[test]
    fn test_rsa_oaep_2048_sha1() {
        let mut rsa_oaep = RsaOaep::<32, 16, Sha1>::new();
        let (pk, sk) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"SHA-1 test".to_vec(),
            l: b"label".to_vec(),
        };
        let c = rsa_oaep.enc(&msg, &pk);
        let d = rsa_oaep.dec(&c, &sk);

        assert_eq!(msg.m, d.m);
    }

    #[test]
    fn test_rsa_oaep_2048_sha256() {
        let mut rsa_oaep = RsaOaep::<32, 16, Sha256>::new();
        let (pk, sk) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"SHA-256 test".to_vec(),
            l: b"".to_vec(),
        };
        let c = rsa_oaep.enc(&msg, &pk);
        let d = rsa_oaep.dec(&c, &sk);

        assert_eq!(msg.m, d.m);
    }

    #[test]
    fn test_rsa_oaep_2048_sha384() {
        let mut rsa_oaep = RsaOaep::<32, 16, Sha384>::new();
        let (pk, sk) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"SHA-384 test".to_vec(),
            l: b"".to_vec(),
        };
        let c = rsa_oaep.enc(&msg, &pk);
        let d = rsa_oaep.dec(&c, &sk);

        assert_eq!(msg.m, d.m);
    }

    #[test]
    fn test_rsa_oaep_2048_sha512() {
        let mut rsa_oaep = RsaOaep::<32, 16, Sha512>::new();
        let (pk, sk) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"SHA-512 test".to_vec(),
            l: b"".to_vec(),
        };
        let c = rsa_oaep.enc(&msg, &pk);
        let d = rsa_oaep.dec(&c, &sk);

        assert_eq!(msg.m, d.m);
    }

    #[test]
    fn test_rsa_oaep_2048_sha256_randomness() {
        let mut rsa_oaep = RsaOaep::<32, 16, Sha256>::new();
        let (pk, _) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"Randomness test".to_vec(),
            l: b"".to_vec(),
        };
        let c1 = rsa_oaep.enc(&msg, &pk);
        let c2 = rsa_oaep.enc(&msg, &pk);
        // They shouldn't be the same since OAEP introduced randomness
        assert_ne!(c1.c, c2.c);
    }
}

#[cfg(test)]
mod tests_anamorphic {
    use super::*;
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    #[test]
    fn test_rsa_oaep_anamorphic_sha1() {
        let mut rsa_oaep_anam = RsaOaepAnam::<32, 16, Sha1>::new();
        let (pk, sk) = rsa_oaep_anam.rsa_oaep.r#gen();

        let dk = rsa_oaep_anam.a_gen(&sk, &pk);
        let msg = RsaOaepMsg {
            m: b"message".to_vec(),
            l: b"label".to_vec(),
        };
        let cm = vec![255u8; 20];

        let c = rsa_oaep_anam.a_enc(&dk, &msg, &cm).unwrap();

        let d = rsa_oaep_anam.rsa_oaep.dec(&c, &sk);
        assert_eq!(d.m, msg.m);

        let dk_recv = RsaOaepDK {
            sk: sk.clone(),
            pk: pk.clone(),
            k: dk.k.clone(),
            ctr: std::sync::atomic::AtomicU64::new(0),
        };

        let cm_d = rsa_oaep_anam.a_dec(&dk_recv, &c).unwrap();
        assert_eq!(cm_d, cm);
    }

    #[test]
    fn test_rsa_oaep_anamorphic_sha256() {
        let mut rsa_oaep_anam = RsaOaepAnam::<32, 16, Sha256>::new();
        let (pk, sk) = rsa_oaep_anam.rsa_oaep.r#gen();

        let dk = rsa_oaep_anam.a_gen(&sk, &pk);
        let msg = RsaOaepMsg {
            m: b"message".to_vec(),
            l: b"label".to_vec(),
        };
        let cm = vec![67u8; 32];

        let c = rsa_oaep_anam.a_enc(&dk, &msg, &cm).unwrap();

        let d = rsa_oaep_anam.rsa_oaep.dec(&c, &sk);
        assert_eq!(d.m, msg.m);

        // We need another DK to decrypt since CTR increments
        let dk_recv = RsaOaepDK {
            sk: sk.clone(),
            pk: pk.clone(),
            k: dk.k.clone(),
            ctr: std::sync::atomic::AtomicU64::new(0),
        };

        let cm_d = rsa_oaep_anam.a_dec(&dk_recv, &c).unwrap();
        assert_eq!(cm_d, cm);
    }

    #[test]
    fn test_rsa_oaep_anamorphic_sha512() {
        let mut rsa_oaep_anam = RsaOaepAnam::<32, 16, Sha512>::new();
        let (pk, sk) = rsa_oaep_anam.rsa_oaep.r#gen();

        let dk = rsa_oaep_anam.a_gen(&sk, &pk);
        let msg = RsaOaepMsg {
            m: b"message".to_vec(),
            l: b"label".to_vec(),
        };
        let cm = vec![255u8; 64];

        let c = rsa_oaep_anam.a_enc(&dk, &msg, &cm).unwrap();

        let d = rsa_oaep_anam.rsa_oaep.dec(&c, &sk);
        assert_eq!(d.m, msg.m);

        let dk_recv = RsaOaepDK {
            sk: sk.clone(),
            pk: pk.clone(),
            k: dk.k.clone(),
            ctr: std::sync::atomic::AtomicU64::new(0),
        };

        let cm_d = rsa_oaep_anam.a_dec(&dk_recv, &c).unwrap();
        assert_eq!(cm_d, cm);
    }
}
