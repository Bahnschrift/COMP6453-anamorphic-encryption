use anamorphic_encryption::pke::{AnamorphicPKE, PKE};
use anamorphic_encryption::rsa_oaep::{RsaOaep, RsaOaepAnam, RsaOaepMsg};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::bench_utils::PkeBenchProvider;

pub struct BenchRsaOaep2048Sha256;

impl PkeBenchProvider for BenchRsaOaep2048Sha256 {
    type Base = RsaOaep<32, 16, Sha256>;
    type Anam = RsaOaepAnam<32, 16, Sha256>;

    // For 2048-bit modulus + SHA-256: max msg = k - 2*h_len - 2 = 256 - 64 - 2 = 190 bytes
    const MAX_MSG_BYTES: usize = 190;

    fn name() -> &'static str {
        "RsaOaep_2048_Sha256"
    }

    fn setup_base() -> Self::Base {
        RsaOaep::new()
    }

    fn setup_anam(_l: u32) -> Self::Anam {
        // RSA-OAEP has no covert-message-space parameter. The covert size is fixed
        // by the hash function's output length. `l` is accepted to satisfy the trait
        // signature but ignored.
        RsaOaepAnam::new()
    }

    fn covert_msg_size_test_cases() -> Vec<u32> {
        // RSA-OAEP covert capacity is determined by H::output_size() (32 B for SHA-256),
        // not by a runtime parameter. The generic `bench_anamorphic_pke` sweep is
        // therefore replaced by a single run; the meaningful sweeps (hash function
        // and modulus size) are in `extra_benches`.
        vec![32]
    }

    fn sample_msg(_pke: &mut Self::Base) -> <Self::Base as PKE>::M {
        RsaOaepMsg {
            m: b"Benchmark payload message".to_vec(),
            l: b"".to_vec(),
        }
    }

    fn sample_covert_msg(_anam: &mut Self::Anam) -> <Self::Anam as AnamorphicPKE<Self::Base>>::CM {
        // Covert message length must equal H::output_size(). SHA-256 → 32 bytes.
        vec![42u8; 32]
    }

    /// RSA-OAEP specific benchmarks:
    ///   1. Hash-function sweep (SHA-1 / SHA-256 / SHA-512) at 2048-bit modulus.
    ///   2. Modulus-size sweep (2048 / 3072 / 4096) at SHA-256.
    ///   3. Corrected covert-channel throughput. The generic `bench_throughput` in
    ///      bench_utils computes covert bits as `log2(l)`, which for `l=256` gives 8
    ///      bits — valid for the rejection-sampling schemes but a 32× understatement
    ///      for RSA-OAEP, whose actual covert payload is `h_len * 8 = 256` bits.
    fn extra_benches(c: &mut criterion::Criterion) {
        use criterion::{BenchmarkId, Throughput, black_box};

        // Helper: run a_enc and a_dec benchmarks for a given concrete instantiation.
        macro_rules! run_anam_case {
            ($group:expr, $label:expr, $base_ty:ty, $anam_ty:ty, $cm_len:expr) => {{
                let mut base = <$base_ty>::new();
                let (pk, sk) = base.r#gen();
                let mut anam = <$anam_ty>::new();
                let dk = anam.a_gen(&sk, &pk);

                let msg = RsaOaepMsg {
                    m: b"Benchmark payload message".to_vec(),
                    l: b"".to_vec(),
                };
                let cm = vec![42u8; $cm_len];

                $group.bench_with_input(
                    BenchmarkId::new("a_enc", $label),
                    &(),
                    |b, _| {
                        b.iter(|| anam.a_enc(black_box(&dk), black_box(&msg), black_box(&cm)))
                    },
                );

                // The counter in dk increments on every a_enc. For the a_dec bench we
                // generate one ciphertext up front; a_dec will XOR-recover a different
                // cm each iteration (because the counter advances), but the timing is
                // independent of counter value and no panic is possible.
                let cipher = anam
                    .a_enc(&dk, &msg, &cm)
                    .expect("a_enc failed during bench setup");

                $group.bench_with_input(
                    BenchmarkId::new("a_dec", $label),
                    &(),
                    |b, _| b.iter(|| anam.a_dec(black_box(&dk), black_box(&cipher))),
                );
            }};
        }

        // 1. Hash-function sweep at 2048-bit modulus.
        let mut hash_group = c.benchmark_group("RsaOaep_2048_HashSweep");
        hash_group.sample_size(10);
        run_anam_case!(
            hash_group,
            "Sha1",
            RsaOaep<32, 16, Sha1>,
            RsaOaepAnam<32, 16, Sha1>,
            20
        );
        run_anam_case!(
            hash_group,
            "Sha256",
            RsaOaep<32, 16, Sha256>,
            RsaOaepAnam<32, 16, Sha256>,
            32
        );
        run_anam_case!(
            hash_group,
            "Sha512",
            RsaOaep<32, 16, Sha512>,
            RsaOaepAnam<32, 16, Sha512>,
            64
        );
        hash_group.finish();

        // 2. Modulus-size sweep at SHA-256.
        // Note: 4096-bit RSA key generation is slow; criterion will auto-reduce samples.
        let mut mod_group = c.benchmark_group("RsaOaep_Sha256_ModulusSweep");
        mod_group.sample_size(10);
        run_anam_case!(
            mod_group,
            2048,
            RsaOaep<32, 16, Sha256>,
            RsaOaepAnam<32, 16, Sha256>,
            32
        );
        run_anam_case!(
            mod_group,
            3072,
            RsaOaep<48, 24, Sha256>,
            RsaOaepAnam<48, 24, Sha256>,
            32
        );
        run_anam_case!(
            mod_group,
            4096,
            RsaOaep<64, 32, Sha256>,
            RsaOaepAnam<64, 32, Sha256>,
            32
        );
        mod_group.finish();

        // 3. Corrected covert-channel throughput for 2048-bit + SHA-256.
        //    True covert capacity per ciphertext = h_len * 8 = 256 bits.
        let mut thr_group = c.benchmark_group("RsaOaep_2048_Sha256/Throughput_Corrected");
        thr_group.sample_size(10);

        let mut base = RsaOaep::<32, 16, Sha256>::new();
        let (pk, sk) = base.r#gen();
        let mut anam = RsaOaepAnam::<32, 16, Sha256>::new();
        let dk = anam.a_gen(&sk, &pk);
        let msg = RsaOaepMsg {
            m: b"Benchmark payload message".to_vec(),
            l: b"".to_vec(),
        };
        let cm = vec![42u8; 32];

        thr_group.throughput(Throughput::Elements(256));
        thr_group.bench_function("Anamorphic Enc Throughput (Covert Bits/s)", |b| {
            b.iter(|| anam.a_enc(black_box(&dk), black_box(&msg), black_box(&cm)))
        });

        thr_group.throughput(Throughput::Bytes(Self::MAX_MSG_BYTES as u64));
        thr_group.bench_function("Standard Enc Throughput (Bytes/s)", |b| {
            b.iter(|| base.enc(black_box(&msg), black_box(&pk)))
        });

        thr_group.finish();
    }
}

crate::impl_pke_benches!(BenchRsaOaep2048Sha256);
