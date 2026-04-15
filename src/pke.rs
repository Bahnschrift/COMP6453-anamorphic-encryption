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
    fn enc(&mut self, m: Self::M, pk: Self::PK) -> Self::C;

    /// Decodes a ciphertext using the private key
    fn dec(&mut self, c: Self::C, sk: Self::SK) -> Self::M;
}

pub trait AnamorphicPKE: PKE {}
