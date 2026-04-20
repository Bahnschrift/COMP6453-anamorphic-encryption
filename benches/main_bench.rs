mod bench_utils;
mod elgamal_bench;

use criterion::{criterion_group, criterion_main};

criterion_group!(benches, elgamal_bench::run_all);
criterion_main!(benches);
