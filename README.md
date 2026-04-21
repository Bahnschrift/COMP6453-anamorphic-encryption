# COMP6453 Term Project -- Anamorophic Encryption

An implementation of Anamorphic ElGamal and Cramer-Shoup in rust encrpytions as per https://eprint.iacr.org/2023/249.pdf.

For ElGamal, we have followed _constructions 5_ and _9_ from the paper, and for Cramer-Shoup we have followed _constructions 7_ and _10_.

## Building and Running

All functionality has been implemented purely as a rust crate (library). We do not provide a command line interface, partially due to the non-portability of anamorphic double keys without recomputing lookup tables on every run.

The library may be built to machine-dependent object files with `cargo build --release`, though the recommended way to use it is simply by importing it into another cargo project with `cargo add --git https://github.com/Bahnschrift/COMP6453-anamorphic-encryption.git`.

## Documentation

We've included extensive documentation as [rustdoc](https://doc.rust-lang.org/rustdoc/index.html) within our code.

After cloning, this documentation can be viewed in the web browser with `cargo doc --open`, or in `./target/doc/anamorphpic_encrytion/index.html` after running `cargo doc.`

Alternatively, since rustdoc transforms comments into documentation, all documentation may also be read directly from within the source code.

## Running Tests

Unit tests are included in test _modules_ at the bottom of each file, and may be run with `cargo test`. Note that runs tests in debug mode by default (with extra safety guarantees from the compiler, without optimisations, etc.). Some tests will take a very long time to run in debug mode, so we recommend instead running in release mode with `cargo run --release`.

## Benchmarking

## Other Notes

As per the spec, we've also included a `Makefile`, with commands for building, testing, and benchmarking. These are all just aliased to the `cargo` commands listed in the above sections.
