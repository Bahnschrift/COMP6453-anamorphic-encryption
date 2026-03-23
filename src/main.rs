use clap::{Parser, Subcommand};
use crypto_bigint::{U2048, U4096};

use crate::el_gamal_pke::{ElGamalPKE, Q};

mod el_gamal_pke;

// Just setting this up for normal PKE encrpytion rn.
// We'll need to rethink the CLI later once we add anamorphic too.
#[derive(Parser, Debug, Clone)]
struct Args {
    #[command(subcommand)]
    mode: ElGamalPKEMode,
}

#[derive(Subcommand, Debug, Clone)]
enum ElGamalPKEMode {
    Gen {},
    Enc { pk: String, m: String },
    Dec { sk: String, c1: String, c2: String },
}

// This return type just means that we propagate errors from any result type up
// to main by using the ? operator.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut pke = ElGamalPKE::new();
    match args.mode {
        ElGamalPKEMode::Gen {} => {
            let (sk, pk) = pke.r#gen();
            println!("pk: {}", pk);
            println!("sk: {}", sk);
        }
        ElGamalPKEMode::Enc { pk, m } => {
            // TODO: Parse these without panicking
            let pk = U4096::from_be_hex(pk.as_str());
            let m = U4096::from_be_hex(format!("{:0>1024}", m).as_str());

            if let Some((c1, c2)) = pke.enc(pk, m) {
                println!("c1: {}", c1);
                println!("c2: {}", c2);
            } else {
                eprintln!("The message is not in the message space.");
            }
        }
        #[allow(unused)]
        ElGamalPKEMode::Dec { sk, c1, c2 } => {
            let sk = U4096::from_be_hex(sk.as_str());
            let c1 = U4096::from_be_hex(c1.as_str());
            let c2 = U4096::from_be_hex(c2.as_str());

            let m = pke.dec(sk, (c1, c2));
            println!("m: {}", m);
        }
    }

    Ok(())
}
