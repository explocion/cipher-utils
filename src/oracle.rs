use cipher::{
    rand_core::{CryptoRng, RngCore},
    Key, KeyInit,
};

use crate::{cli::Command, DefaultKey};
use std::{fs, path::Path};

pub trait CipherOracle: KeyInit + DefaultKey {
    type DecryptError: std::error::Error;

    fn challenge_cipher_text() -> &'static str;
    fn challenge_cipher_bytes() -> &'static [u8];
    fn encrypt(key: &Key<Self>, rng: impl CryptoRng + RngCore, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(key: &Key<Self>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::DecryptError>;

    fn key_from_file<P: AsRef<Path>>(path: P) -> Key<Self> {
        let hex = fs::read_to_string(path).expect("failed to read key hex from file");
        let bytes = hex::decode(hex.trim()).expect("failed to decode key hex to bytes");
        Key::<Self>::clone_from_slice(&bytes)
    }

    #[inline]
    fn key_from_file_or_default<P: AsRef<Path>>(path: Option<P>) -> Key<Self> {
        match path {
            Some(path) => Self::key_from_file(path),
            None => Self::default_key(),
        }
    }

    fn bootstrap(plaintext: &str) {
        let key_in_bytes = Self::generate_key(rand::thread_rng());
        let ciphertext = Self::encrypt(&key_in_bytes, rand::thread_rng(), plaintext.as_bytes());
        println!("key: {}", hex::encode(&key_in_bytes));
        println!("plaintext: {}", &plaintext);
        println!("ciphertext: {}", hex::encode(&ciphertext));
    }

    fn execute_as_cli(cmd: Command) {
        match cmd {
            Command::Generate => println!(
                "{}",
                hex::encode(Self::generate_key(rand::thread_rng()).as_slice())
            ),
            Command::Encrypt(bytes, key) => {
                let key = Self::key_from_file_or_default(key);
                let ciphertext = Self::encrypt(&key, rand::thread_rng(), &bytes);
                println!("{}", hex::encode(ciphertext));
            }
            Command::Decrypt(bytes, None) if bytes == Self::challenge_cipher_bytes() => {
                println!("cheater: it is forbidden to decrypt the challenge ciphertext");
            }
            Command::Decrypt(bytes, key) => {
                let key = Self::key_from_file_or_default(key);
                let plaintext = Self::decrypt(&key, &bytes).expect("failed to decrypt");
                println!(
                    "{}",
                    String::from_utf8(plaintext)
                        .expect("failed to encode decrypted bytes to valid UTF-8 string")
                );
            }
        }
    }
}
