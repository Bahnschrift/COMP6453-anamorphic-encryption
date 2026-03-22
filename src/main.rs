use clap::{Parser, Subcommand};

use crate::el_gamal_pke::ElGamalPKE;

mod el_gamal_pke;

// Just setting this up for normal PKE encrpytion rn.
// We'll need to rethink the CLI later once we add anamorphic too.
#[derive(Parser, Debug, Clone)]
struct Args {
    /// Some large prime
    p: u32,
    /// Generator
    g: u32,

    #[command(subcommand)]
    mode: ElGamalPKEMode,
}

#[derive(Subcommand, Debug, Clone)]
enum ElGamalPKEMode {
    Gen {},
    Enc { pk: u32, m: u32 },
    Dec { sk: u32, c1: u32, c2: u32 },
}

// This return type just means that we propagate errors from any result type up
// to main by using the ? operator.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut pke = ElGamalPKE::new(args.p, args.g);
    match args.mode {
        ElGamalPKEMode::Gen {} => {
            let (pk, sk) = pke.r#gen();
            println!("pk: {}, sk: {}", pk, sk);
        }
        ElGamalPKEMode::Enc { pk, m } => {
            if let Some((c1, c2)) = pke.enc(pk, m) {
                println!("c1: {}, c2: {}", c1, c2);
            } else {
                eprintln!("The message {} is not in the message space.", m);
            }
        }
        #[allow(unused)]
        ElGamalPKEMode::Dec { sk, c1, c2 } => todo!(),
    }

    Ok(())
}
