use anamorphic_encryption::cramer_shoup::{CramerShoup, CramerShoupAnam};
use anamorphic_encryption::groups::{Group2048, MCG};
use anamorphic_encryption::pke::{AnamorphicPKE, PKE};
use crypto_bigint::Uint;

use crate::bench_utils::PkeBenchProvider;

pub struct BenchCramerShoup2048;

impl PkeBenchProvider for BenchCramerShoup2048 {
    type Base = CramerShoup<32, Group2048>;
    type Anam = CramerShoupAnam<32, Group2048>;
    const MAX_MSG_BYTES: usize = 255;

    fn name() -> &'static str {
        "CramerShoup_2048"
    }

    fn setup_base() -> Self::Base {
        CramerShoup::new()
    }

    fn setup_anam(l: u32) -> Self::Anam {
        CramerShoupAnam::new(l, 256, 256)
    }

    fn covert_msg_size_test_cases() -> Vec<u32> {
        vec![64, 128, 256, 512]
    }

    fn sample_msg(_pke: &mut Self::Base) -> <Self::Base as PKE>::M {
        let num = Uint::<32>::from_u32(42);
        Group2048::from_modq(num).unwrap()
    }

    fn sample_covert_msg(_anam: &mut Self::Anam) -> <Self::Anam as AnamorphicPKE<Self::Base>>::CM {
        42
    }

    /// Benchmark Anamorphic Cramer-Shoup with different s and t params, l fixed at 256.
    fn extra_benches(c: &mut criterion::Criterion) {
        use criterion::{BenchmarkId, black_box};

        let mut group = c.benchmark_group("CramerShoup_2048_Params_Sweep");
        group.sample_size(10); // Keep it fast

        let l = 256;
        let t = 256;
        let s_cases = [64, 128, 256, 512];

        for picked_s in s_cases {
            group.bench_with_input(
                BenchmarkId::new("a_enc_s_sweep", picked_s),
                &picked_s,
                |b, &s| {
                    let mut anam_pke = CramerShoupAnam::<32, Group2048>::new(l, s, t);
                    let mut base_pke = CramerShoup::<32, Group2048>::new();

                    let (pk, sk) = base_pke.r#gen();
                    let dk = anam_pke.a_gen(&sk, &pk);
                    let num = Uint::<32>::from_u32(42);
                    let msg = Group2048::from_modq(num).unwrap();
                    let covert_msg = 42;

                    b.iter(|| {
                        anam_pke.a_enc(
                            black_box(&dk),
                            black_box(&msg),
                            black_box(&covert_msg),
                        )
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("a_dec_s_sweep", picked_s),
                &picked_s,
                |b, &s| {
                    let mut anam_pke = CramerShoupAnam::<32, Group2048>::new(l, s, t);
                    let mut base_pke = CramerShoup::<32, Group2048>::new();

                    let (pk, sk) = base_pke.r#gen();
                    let dk = anam_pke.a_gen(&sk, &pk);
                    let num = Uint::<32>::from_u32(42);
                    let msg = Group2048::from_modq(num).unwrap();
                    let covert_msg = 42;
                    let cipher = anam_pke
                        .a_enc(&dk, &msg, &covert_msg)
                        .expect("a_enc failed");

                    b.iter(|| anam_pke.a_dec(black_box(&dk), black_box(&cipher)));
                },
            );
        }

        let s = 256;
        let t_cases = [64, 128, 256, 512];

        for picked_t in t_cases {
            group.bench_with_input(
                BenchmarkId::new("a_enc_t_sweep", picked_t),
                &picked_t,
                |b, &t| {
                    let mut anam_pke = CramerShoupAnam::<32, Group2048>::new(l, s, t);
                    let mut base_pke = CramerShoup::<32, Group2048>::new();

                    let (pk, sk) = base_pke.r#gen();
                    let dk = anam_pke.a_gen(&sk, &pk);
                    let num = Uint::<32>::from_u32(42);
                    let msg = Group2048::from_modq(num).unwrap();
                    let covert_msg = 42;

                    b.iter(|| {
                        anam_pke.a_enc(
                            black_box(&dk),
                            black_box(&msg),
                            black_box(&covert_msg),
                        )
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("a_dec_t_sweep", picked_t),
                &picked_t,
                |b, &t| {
                    let mut anam_pke = CramerShoupAnam::<32, Group2048>::new(l, s, t);
                    let mut base_pke = CramerShoup::<32, Group2048>::new();

                    let (pk, sk) = base_pke.r#gen();
                    let dk = anam_pke.a_gen(&sk, &pk);
                    let num = Uint::<32>::from_u32(42);
                    let msg = Group2048::from_modq(num).unwrap();
                    let covert_msg = 42;
                    let cipher = anam_pke
                        .a_enc(&dk, &msg, &covert_msg)
                        .expect("a_enc failed");

                    b.iter(|| anam_pke.a_dec(black_box(&dk), black_box(&cipher)));
                },
            );
        }

        group.finish();
    }
}

crate::impl_pke_benches!(BenchCramerShoup2048);
