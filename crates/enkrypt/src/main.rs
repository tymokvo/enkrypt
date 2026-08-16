use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    key: String,
    payload: String,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    dbg!(args.key);
    dbg!(args.payload);

    let key = Key::<Aes256Gcm>::generate();

    let nonce = Nonce::<_>::generate();

    let cipher = Aes256Gcm::new(&key);

    let bytes = "hello".bytes().collect::<Vec<_>>();

    let ciphertext = cipher
        .encrypt(&nonce, bytes.as_slice())
        .map_err(|e| format!("{e}"))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| format!("{e}"))?;

    dbg!(String::from_utf8(plaintext));
    dbg!(ciphertext);
    dbg!(key);

    Ok(())
}
