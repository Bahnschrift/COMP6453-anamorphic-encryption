use anamorphic_encryption::pke::{AnamorphicPKE, PKE};
use criterion::{BenchmarkId, Criterion, Throughput, black_box};

/// State and data provider for benchmarking standard PKE / Anamorphic algorithms.
pub trait PkeBenchProvider {
    type Base: PKE;
    type Anam: AnamorphicPKE<Self::Base>;

    /// Display name for the criterion group
    fn name() -> &'static str;

    /// Instantiate standard PKE algorithm
    fn setup_base() -> Self::Base;

    /// Instantiate anamorphic PKE algorithm.
    /// Takes l as the covert message space parameter.
    fn setup_anam(l: u32) -> Self::Anam;

    /// Supported test cases for l (e.g. [64, 128, 256, 512]).
    fn covert_msg_size_test_cases() -> Vec<u32>;

    /// A valid message for standard PKE
    fn sample_msg(pke: &mut Self::Base) -> <Self::Base as PKE>::M;

    /// A valid covert message for anamorphic encryption
    fn sample_covert_msg(anam: &mut Self::Anam) -> <Self::Anam as AnamorphicPKE<Self::Base>>::CM;

    /// Maximum message size in bytes
    const MAX_MSG_BYTES: usize;

    /// Optional scheme-specific benchmarks
    fn extra_benches(c: &mut Criterion) -> ();
}

// Benchmark Runners

pub fn bench_standard_pke<Bench: PkeBenchProvider>(c: &mut Criterion) {
    let mut pke = Bench::setup_base();
    let (pk, sk) = pke.r#gen();
    let msg = Bench::sample_msg(&mut pke);

    let group_name = format!("{}/Standard", Bench::name());
    let mut group = c.benchmark_group(&group_name);

    group.bench_function("gen", |b| b.iter(|| pke.r#gen()));

    group.bench_function("enc", |b| {
        b.iter(|| pke.enc(black_box(&msg), black_box(&pk)))
    });

    let cipher = pke.enc(&msg, &pk);
    group.bench_function("dec", |b| {
        b.iter(|| pke.dec(black_box(&cipher), black_box(&sk)))
    });

    group.finish();
}

pub fn bench_anamorphic_pke<Bench: PkeBenchProvider>(c: &mut Criterion) {
    let mut base_pke = Bench::setup_base();
    let (pk, sk) = base_pke.r#gen();

    let group_name = format!("{}/Anamorphic", Bench::name());
    let mut group = c.benchmark_group(&group_name);
    group.sample_size(10); // Keep it fast

    for l in Bench::covert_msg_size_test_cases() {
        group.bench_with_input(BenchmarkId::new("a_gen", l), &l, |b, &l| {
            let mut anam_pke = Bench::setup_anam(l);
            b.iter(|| anam_pke.a_gen(black_box(&sk), black_box(&pk)))
        });
    }
    group.finish();

    let mut group2 = c.benchmark_group(format!("{}/Anamorphic", Bench::name()));
    group2.sample_size(10);

    for l in Bench::covert_msg_size_test_cases() {
        let mut anam_pke = Bench::setup_anam(l);
        let dk = anam_pke.a_gen(&sk, &pk);
        let msg = Bench::sample_msg(&mut base_pke);
        let covert_msg = Bench::sample_covert_msg(&mut anam_pke);

        group2.bench_with_input(BenchmarkId::new("a_enc", l), &l, |b, &_| {
            b.iter(|| {
                anam_pke.a_enc(
                    black_box(&dk),
                    black_box(&msg),
                    black_box(&covert_msg),
                )
            })
        });

        let anam_cipher = anam_pke
            .a_enc(&dk, &msg, &covert_msg)
            .expect("a_enc failed");

        group2.bench_with_input(BenchmarkId::new("a_dec", l), &l, |b, &_| {
            b.iter(|| anam_pke.a_dec(black_box(&dk), black_box(&anam_cipher)))
        });
    }
    group2.finish();
}

pub fn bench_throughput<Bench: PkeBenchProvider>(c: &mut Criterion) {
    let mut base_pke = Bench::setup_base();

    // Pick the first l test case for throughput baseline
    let l = 256;
    let mut anam_pke = Bench::setup_anam(l);

    let (pk, sk) = base_pke.r#gen();
    let dk = anam_pke.a_gen(&sk, &pk);
    let msg = Bench::sample_msg(&mut base_pke);
    let covert_msg = Bench::sample_covert_msg(&mut anam_pke);

    let mut group = c.benchmark_group(format!("{}/Throughput", Bench::name()));
    group.sample_size(10);

    // Simulate bulk throughput by computing Bytes/Sec for standard encryption
    // For covert payload, l represents the message space. The capacity in bits is log2(l).
    // We use `Throughput::Elements` to treat each element as 1 bit, so the output will be displayed as "elements/s" (equivalent to bits/s).
    let covert_bits = (l as f64).log2().floor() as u64;

    group.throughput(Throughput::Bytes(Bench::MAX_MSG_BYTES as u64));
    group.bench_function("Standard Enc Throughput (Bytes/s)", |b| {
        b.iter(|| base_pke.enc(black_box(&msg), black_box(&pk)))
    });

    group.throughput(Throughput::Elements(covert_bits));
    group.bench_function("Anamorphic Enc Throughput (Covert Bits/s)", |b| {
        b.iter(|| {
            anam_pke.a_enc(
                black_box(&dk),
                black_box(&msg),
                black_box(&covert_msg),
            )
        })
    });

    group.finish();
}

#[macro_export]
macro_rules! impl_pke_benches {
    ($type:ty) => {
        pub fn run_all(c: &mut criterion::Criterion) {
            crate::bench_utils::bench_standard_pke::<$type>(c);
            crate::bench_utils::bench_anamorphic_pke::<$type>(c);
            crate::bench_utils::bench_throughput::<$type>(c);
            <$type as crate::bench_utils::PkeBenchProvider>::extra_benches(c);
        }
    };
}
