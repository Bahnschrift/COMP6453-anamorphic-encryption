//! # COMP6453 Term Project -- Anamorphic Encryption
//!
//! This crate contains implementations of _anamorphic encryption_ over ElGamal and Cramer-Shoup
//! PKE schemes as described in <https://eprint.iacr.org/2023/249.pdf>.
//!
//! ## Anamorphic Encryption
//! Anamorphic encryption is the idea of embedding an additional _covert_ message within
//! an existing message encrypted using a public key encryption (PKE) scheme. The covert message
//! is encrypted alongside the normal message using the _double key_ (dk) combined with the
//! normal _secret key_ (sk), and may then be decrypted using dk combined with the normal
//! _public key_ (pk).
//!
//! ## Project Structure
//! - Traits (interfaces) for both [`pke::PKE`] and [`pke::AnamorphicPKE`] are defined in [`pke`].
//!   This is the logical starting point for reading through the code.
//! - Both ElGamal and Cramer-Shoup are defined over cyclic groups. Here, we use prime order cyclic
//!   groups. Membership of these groups is enforced at a type level, with groups being defined [`groups`].
//! - [`helpers`] contains various helper functions.
//! - [`el_gamal`] and [`cramer_shoup`] contain implementations of both [`pke::PKE`]
//!   and [`pke::AnamorphicPKE`] for the respective PKE schemes.
//! - Unit tests are included in `tests` modules at the bottom of each relevant file.
//!
//! ## Arithmetic
//! We use the [`crypto_bigint`] crate for large unsigned integer support. Integers in this crate
//! are defined over a specified number of _limbs_, with each limb being capable of storing 64 bytes, i.e.
//! a single-limbed unsigned integer is equivalent to a `U64`. A consequence of this is that much of our code
//! follows the same pattern to ensure compatibility.
//!
//! Additionally, [`crypto_bigint`] provides [`crypto_bigint::modular::ConstMontyForm`], which provides an
//! alternative integer representation to provide fast modular arithmetic. We make extensive use of this in
//! our multiplicative cyclic group implementations in [`groups::MCG`].

pub mod cramer_shoup;
pub mod el_gamal;
pub mod groups;
pub mod helpers;
pub mod pke;
pub mod rsa;
