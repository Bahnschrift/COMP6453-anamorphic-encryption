/// Defines the functions required for standard public key encryption.
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

pub trait AnamorphicPKE<P: PKE> {
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
    fn a_enc(&mut self, pk: &P::PK, dk: &Self::DK, m: &P::M, cm: &Self::CM) -> Option<P::C>;

    /// Anamorphic decryption.
    ///
    /// Returns `None` if `c` does not contain a covert message under `dk`.
    fn a_dec(&mut self, dk: &Self::DK, c: &P::C) -> Option<Self::CM>;
}
