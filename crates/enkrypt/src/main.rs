use argon2::Argon2;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload, array::Array},
};
use clap::{Parser, Subcommand};
use rand::{Rng, rngs::ChaCha12Rng};

const SALT_BYTE_LENGTH: usize = 16;
const NONCE_BYTE_LENGTH: usize = 24;

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
    let args = Args::parse();

    let mut rng: ChaCha12Rng = rand::make_rng();

    let argon = Argon2::default();

    match args.mode {
        Mode::Encrypt { cleartext } => {
            let salt = {
                let mut salt = [0u8; SALT_BYTE_LENGTH];
                rng.fill_bytes(&mut salt);
                salt
            };

            let key = {
                let mut output_key = [0u8; 32];

                argon
                    .hash_password_into(args.key.as_bytes(), &salt, &mut output_key)
                    .map_err(|e| format!("{e}"))?;

                output_key
            };

            let key_array: Array<_, _> = key.try_into().map_err(|e| format!("{e}"))?;
            let cipher = XChaCha20Poly1305::new(&key_array);
            let nonce = XNonce::generate();

            let cipherbytes = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: cleartext.as_bytes(),
                        aad: &salt,
                    },
                )
                .map_err(|e| format!("{e}"))?;

            let mut output = vec![];

            output.append(&mut salt.to_vec());
            output.append(&mut nonce.to_vec());
            output.append(&mut cipherbytes.to_vec());

            println!("{}", b64.encode(output.as_slice()));

            Ok(())
        }
        Mode::Decrypt { ciphertext } => {
            let bytes = b64.decode(&ciphertext).map_err(|e| format!("{e}"))?;

            let (salt, nonce_cipher) = bytes.split_at(SALT_BYTE_LENGTH);
            let (noncebytes, cipherbytes) = nonce_cipher.split_at(NONCE_BYTE_LENGTH);

            let nonce = if noncebytes.len() == NONCE_BYTE_LENGTH {
                let nonce_array: [u8; NONCE_BYTE_LENGTH] =
                    noncebytes.try_into().map_err(|e| format!("{e}"))?;

                XNonce::try_from(nonce_array).map_err(|e| format!("{e}"))?
            } else {
                return Err("could not reconstruct nonce".into());
            };

            let key = {
                let mut output_key = [0u8; 32];

                argon
                    .hash_password_into(args.key.as_bytes(), &salt, &mut output_key)
                    .map_err(|e| format!("{e}"))?;

                output_key
            };

            let key_array: Array<_, _> = key.try_into().map_err(|e| format!("{e}"))?;
            let cipher = XChaCha20Poly1305::new(&key_array);

            let clearbytes = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: cipherbytes,
                        aad: salt,
                    },
                )
                .map_err(|e| format!("{e}"))?;

            let cleartext = String::from_utf8(clearbytes).map_err(|e| format!("{e}"))?;

            println!("{}", cleartext);

            Ok(())
        }
    }
}
