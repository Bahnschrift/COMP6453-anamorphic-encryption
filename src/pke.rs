//! # PKE Traits
//!
//! This module defines traits describing the behaviour of both public key encryption ([`PKE`])
//! and anamorphic public key encryption ([`AnamorphicPKE`]).
//!
//! In particular, an effort has been made to be as generic as possible, allowing manual specification
//! over which types these are implemented. This provides a lot more flexibility in terms of supporting
//! a "parse, don't validate" paradigm -- allowing implementers of these traits to define their own types
//! which enforce appropriate guarantees (e.g. [`crate::groups::MCG`]).

use std::ops::Deref;

/// Trait defining the functions and associated types required
/// for public key encryption (PKE).
///
/// PKE consists of three functions: [`PKE::gen`], [`PKE::enc`], and [`PKE::dec`].
/// See the documentation for each of these functions for more information.
pub trait PKE {
    /// Public key
    type PK;

    /// Secret key
    type SK;

    /// Message space
    type M;

    /// Ciphertext space
    type C;

    /// Generates a new public / secret key pair
    fn r#gen(&mut self) -> (Self::PK, Self::SK);

    /// Encodes a message using the public key
    fn enc(&mut self, m: &Self::M, pk: &Self::PK) -> Self::C;

    /// Decodes a ciphertext using the private key
    fn dec(&mut self, c: &Self::C, sk: &Self::SK) -> Self::M;
}

/// Trait defining the functions and associated types required
/// for _anamorphic_ public key encryption (AnamPKE).
///
/// AnamorphicPKE is defined on top of an existing PKE scheme `P`,
/// and thus requires it as a type parameter.
///
/// It allows you to, as well as the standard encoding of a ciphertext,
/// embed an additional optional "covert message" within a ciphertext,
/// only decodable by those with the "double key".
///
/// It augments this existing scheme with three additional functions:
/// [`AnamorphicPKE::a_gen`], [`AnamorphicPKE::a_enc`], and [`AnamorphicPKE::a_dec`].
pub trait AnamorphicPKE<P: PKE>: Deref<Target = P> {
    /// Double key
    type DK;

    /// Covert message
    type CM;

    /// Anamorphic double key generation.
    fn a_gen(&mut self, sk: &P::SK, pk: &P::PK) -> Self::DK;

    /// Anamorphic encrpytion.
    ///
    /// Returns `None` if `cm` is not a valid covert message.
    ///
    /// Note that this _could_ have be handled at the type level,
    /// requiring `CM` to only contain valid values (and implement an
    /// iter method for `a_gen`), but that will probably make things more
    /// annoying than they need to be.
    fn a_enc(&mut self, dk: &Self::DK, m: &P::M, cm: &Self::CM) -> Option<P::C>;

    /// Anamorphic decryption.
    ///
    /// Returns `None` if `c` does not contain a covert message under `dk`.
    fn a_dec(&mut self, dk: &Self::DK, c: &P::C) -> Option<Self::CM>;
}
