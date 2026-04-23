mod bench_utils;
mod cramer_shoup_bench;
mod elgamal_bench;
mod rsa_oaep_bench;

use criterion::{criterion_group, criterion_main};

criterion_group!(
    benches,
    elgamal_bench::run_all,
    cramer_shoup_bench::run_all,
    rsa_oaep_bench::run_all
);
criterion_main!(benches);
