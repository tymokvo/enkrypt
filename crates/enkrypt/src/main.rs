use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, Generate, Key, KeyInit},
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    key: String,
    payload: String,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let key = Key::<XChaCha20Poly1305>::generate();
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, b"plaintext message".as_ref())
        .map_err(|e| format!("{e}"))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| format!("{e}"))?;

    dbg!(ciphertext);
    dbg!(plaintext);

    Ok(())
}
