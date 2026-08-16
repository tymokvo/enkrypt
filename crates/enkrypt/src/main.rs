use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};
use clap::{Parser, Subcommand};
use sha2::Digest;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    key: String,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Encrypt { cleartext: String },
    Decrypt { ciphertext: String },
}

fn main() -> Result<(), String> {
    println!("starting");

    let args = Args::parse();
    dbg!("args parsed");

    let key = {
        // NOTE: This should be swapped for a key derivation function. There is
        // no salt or multi-round hashing with SHA256, it's just convenient.
        sha2::Sha256::digest(args.key.as_bytes())
    };
    dbg!("key digested");
    let cipher = XChaCha20Poly1305::new(&key);

    match args.mode {
        Mode::Encrypt { cleartext } => {
            println!("encrypting");
            let nonce = XNonce::generate();

            let cipherbytes = cipher
                .encrypt(&nonce, cleartext.as_bytes())
                .map_err(|e| format!("{e}"))?;

            let mut output = vec![];

            output.append(&mut nonce.to_vec());
            output.append(&mut cipherbytes.to_vec());

            println!("{}", b64.encode(output.as_slice()));

            Ok(())
        }
        Mode::Decrypt { ciphertext } => {
            println!("decrypting again");

            let bytes = b64.decode(&ciphertext).map_err(|e| format!("{e}"))?;

            let (noncebytes, cipherbytes) = bytes.split_at(24);

            let nonce = if noncebytes.len() == 24 {
                let nonce_array: [u8; 24] = noncebytes.try_into().map_err(|e| format!("{e}"))?;
                XNonce::try_from(nonce_array).map_err(|e| format!("{e}"))?
            } else {
                return Err("could not reconstruct nonce".into());
            };

            let clearbytes = cipher
                .decrypt(&nonce, cipherbytes)
                .map_err(|e| format!("{e}"))?;

            let cleartext = String::from_utf8(clearbytes).map_err(|e| format!("{e}"))?;

            println!("{}", cleartext);

            Ok(())
        }
    }
}
