use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, Generate, Key, KeyInit},
};
use clap::Parser;
use sha2::Digest;

#[derive(Parser)]
struct Args {
    key: String,
    payload: String,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let key = {
        // NOTE: This should be swapped for a key derivation function. There is
        // no salt or multi-round hashing with SHA256, it's just convenient.
        sha2::Sha256::digest(args.key.as_bytes())
    };
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::generate();

    let cipherbytes = cipher
        .encrypt(&nonce, args.payload.as_bytes())
        .map_err(|e| format!("{e}"))?;

    let plainbytes = cipher
        .decrypt(&nonce, cipherbytes.as_ref())
        .map_err(|e| format!("{e}"))?;

    let plaintext = String::from_utf8(plainbytes).map_err(|e| format!("{e}"))?;

    dbg!(cipherbytes);
    dbg!(plaintext);

    Ok(())
}
