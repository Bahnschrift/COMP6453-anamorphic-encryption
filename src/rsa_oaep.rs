use crypto_bigint::Uint;
use rand::{RngExt, SeedableRng, rngs::ChaCha20Rng};
use rayon::vec;
use sha2::{Digest, Sha256};

use crate::pke::PKE;
use crate::rsa::{RSA, RsaPK, RsaSK};

type RandomSeed = [u8; 32];
type HASHER = Sha256;
const HASH_LEN: usize = 32;
const HASH_FOR_EMPTY_L: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Mask Generation Function 1 (MGF1) using SHA-256
fn mgf(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while mask.len() < mask_len {
        let mut hasher = HASHER::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes()); // 4 bytes, big endian
        let hash = hasher.finalize();
        mask.extend_from_slice(&hash);
        counter += 1;
    }
    mask.truncate(mask_len);

    mask
}

/// Message and label of RSA-OAEP.
/// We place them here to satisfy the PKE trait.
pub struct RsaOaepMsg {
    // We will use Vec and introduce a runtime check for this, or there will need to be another type parameter
    /// The message to be encrypted.
    /// The maximum length of it is k - 2 * h - 2 bytes.
    /// For RSA 2048 (256 bytes) with SHA-256 (32 bytes), this is 190 bytes.
    pub m: Vec<u8>,
    /// Optional label, we are not using SHA-1 so we will skip the length check of it.
    pub l: Vec<u8>,
}

/// RSA-OAEP ciphertext and label
pub struct RsaOaepCiphertext<const MOD_LIMBS: usize> {
    c: Uint<MOD_LIMBS>,
    l: Vec<u8>,
}

/// RSA-OAEP or RSAES-OAEP in RFC 8017 Section 7.1, based on regular RSA PKE scheme
///
/// # Panics:
/// - Panics at compile time if the modulus size is not at least twice the prime size.
pub struct RsaOaep<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> {
    rsa: RSA<MOD_LIMBS, PRIME_LIMBS>,
    rng: ChaCha20Rng,
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> RsaOaep<MOD_LIMBS, PRIME_LIMBS> {
    pub fn new() -> Self {
        Self {
            rsa: RSA::new(),
            rng: ChaCha20Rng::from_seed(rand::rng().random()),
        }
    }

    pub fn new_seeded(seed: RandomSeed) -> Self {
        Self {
            rsa: RSA::new_seeded(seed),
            rng: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl<const MOD_LIMBS: usize, const PRIME_LIMBS: usize> PKE for RsaOaep<MOD_LIMBS, PRIME_LIMBS> {
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
    fn enc(&mut self, Self::M { m, l }: &Self::M, pk: &Self::PK) -> Self::C {
        // We follow the steps given in RFC 8017 Section 7.1.1

        // Length checking
        let k = Uint::<MOD_LIMBS>::BYTES;
        // For SHA-256, this is 32 bytes

        if m.len() > k - 2 * HASH_LEN - 2 {
            panic!("message too long");
        }

        // EME-OAEP encoding
        // Hash the label L
        let l_hash: [u8; HASH_LEN] = if l.is_empty() {
            HASH_FOR_EMPTY_L
        } else {
            let mut hasher = HASHER::new();
            hasher.update(l);
            hasher.finalize().into()
        };

        // Generate padding string PS
        let ps_len = k - m.len() - 2 * HASH_LEN - 2;
        let ps = vec![0u8; ps_len];

        // Construct data block DB
        // DB = lHash || PS || 0x01 || M
        let mut db = Vec::with_capacity(k - HASH_LEN - 1);
        db.extend_from_slice(&l_hash);
        db.extend_from_slice(&ps);
        db.push(0x01);
        db.extend_from_slice(m);

        // Generate random octet string seed of length hLen
        let mut seed = vec![0u8; HASH_LEN];
        self.rng.fill(&mut seed[..]);

        let db_mask = mgf(&seed, k - HASH_LEN - 1);

        let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

        let seed_mask = mgf(&masked_db, HASH_LEN);

        // masked_seed = seed xor seed_mask
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
        Self::C {
            c: self.rsa.enc(&em_int, pk),
            l: l.clone(),
        }
    }

    /// RSA-OAEP decryption, decrypts with standard RSA and then removes OAEP padding to recover the message
    ///
    /// # Panics:
    /// - If the OAEP padding is invalid
    fn dec(&mut self, Self::C { c, l }: &Self::C, sk: &Self::SK) -> Self::M {
        // Still following RFC 8017 Section 7.1.2

        // Length checking
        let k = Uint::<MOD_LIMBS>::BYTES;

        // Recover EM
        let em = self.rsa.dec(c, sk).to_be_bytes();

        // Check for Zero prefix
        if em[0] != 0x00 {
            panic!("decryption error");
        }

        // EME-OAEP decoding
        let l_hash: [u8; HASH_LEN] = if l.is_empty() {
            HASH_FOR_EMPTY_L
        } else {
            let mut hasher = HASHER::new();
            hasher.update(l);
            hasher.finalize().into()
        };

        // Extract components
        let masked_seed = &em[1..1 + HASH_LEN];

        let masked_db = &em[1 + HASH_LEN..];

        // Unmask seed
        let seed_mask = mgf(masked_db, HASH_LEN);
        let seed: Vec<u8> = masked_seed
            .iter()
            .zip(seed_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Unmask DB
        let db_mask = mgf(&seed, k - HASH_LEN - 1);
        let db: Vec<u8> = masked_db
            .iter()
            .zip(db_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Validate lHash
        let expected_l_hash = &db[0..HASH_LEN];
        if l_hash != &expected_l_hash[..] {
            panic!("decryption error");
        }

        // Find exactly where the PS zeroes end and the 0x01 separator starts
        let mut separator_idx = HASH_LEN;
        while separator_idx < db.len() && db[separator_idx] == 0x00 {
            separator_idx += 1;
        }

        // Ensure separator exists and is 0x01
        if separator_idx == db.len() || db[separator_idx] != 0x01 {
            panic!("decryption error");
        }

        // Extract original message M
        Self::M {
            m: db[separator_idx + 1..].to_vec(),
            l: l.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_oaep_2048() {
        // simple enc/dec
        let mut rsa_oaep = RsaOaep::<32, 16>::new_seeded([42u8; 32]);
        let (pk, sk) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"Hello, this is securely padded RSA-OAEP!".to_vec(),
            l: b"".to_vec(),
        };
        let ciphertext = rsa_oaep.enc(&msg, &pk);
        let decrypted = rsa_oaep.dec(&ciphertext, &sk);

        assert_eq!(msg.m, decrypted.m);
    }

    #[test]
    fn test_rsa_oaep_randomness() {
        let mut rsa_oaep = RsaOaep::<32, 16>::new_seeded([42u8; 32]);
        let (pk, _) = rsa_oaep.r#gen();

        let msg = RsaOaepMsg {
            m: b"Confidential String".to_vec(),
            l: b"".to_vec(),
        };
        let ciphertext1 = rsa_oaep.enc(&msg, &pk);
        let ciphertext2 = rsa_oaep.enc(&msg, &pk);
        // They shouldn't be the same since OAEP introduced randomness
        assert_ne!(ciphertext1.c, ciphertext2.c);
    }
}
