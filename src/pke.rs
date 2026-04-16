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
    ///
    /// Returns `None` if anamorphic parameters are not available.
    fn a_gen(&mut self, sk: &P::SK, pk: &P::PK) -> Self::DK;

    fn a_enc(&mut self, dk: &Self::DK, m: &P::M, cm: &Self::CM) -> Option<P::M>;

    fn a_dec(&mut self, dk: &Self::DK, c: &P::C) -> Option<Self::CM>;
}
