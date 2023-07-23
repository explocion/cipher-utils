use cipher::{
    rand_core::{CryptoRng, RngCore},
    KeyInit,
};

use crate::cli::Command;
use std::{io::Write, path::Path};

pub trait CipherOracle: Default + hex::FromHex + KeyInit
where
    Self::Error: std::error::Error,
{
    type DecryptError: std::error::Error;

    fn challenge_cipher_text() -> &'static str;
    fn challenge_cipher_bytes() -> &'static [u8];
    fn encrypt_message(&mut self, rng: impl CryptoRng + RngCore, plain_message: &[u8]) -> Vec<u8>;
    fn decrypt_message(&mut self, encrypted_message: &[u8]) -> Result<Vec<u8>, Self::DecryptError>;

    #[inline]
    fn generate_with(rng: impl CryptoRng + RngCore) -> Self {
        Self::new(&Self::generate_key(rng))
    }

    #[inline]
    fn generate() -> Self {
        Self::generate_with(rand::thread_rng())
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let hex = std::fs::read_to_string(path).expect("Failed to read file");
        let bytes = hex::decode(hex.trim()).expect("Failed to decode hex to bytes");
        Self::from_hex(bytes).expect("Failed to decode hex to cipher key")
    }

    fn bootstrap(plain_message: &str) {
        use cipher::generic_array::GenericArray;
        let key_in_bytes = Self::generate_key(rand::thread_rng());
        let salt_in_bytes = Self::generate_key(rand::thread_rng());
        let salted_key_in_bytes = GenericArray::<u8, Self::KeySize>::from_iter(
            key_in_bytes
                .iter()
                .zip(salt_in_bytes.iter())
                .map(|(a, b)| a ^ b),
        );
        let mut cipher = Self::new(&key_in_bytes);
        let key = hex::encode(key_in_bytes.as_slice());
        println!(
            "{} = {} ^ {}",
            &key,
            hex::encode(salted_key_in_bytes),
            hex::encode(salt_in_bytes)
        );
        let ct = cipher.encrypt_message(rand::thread_rng(), plain_message.as_bytes());
        let ct = hex::encode(ct);
        println!("{}", &ct);
        let mut key_file = std::fs::File::options()
            .create(true)
            .write(true)
            .open("key.txt")
            .expect("Failed to open plaintext.txt");
        write!(key_file, "{}", &key).expect("Failed to write key.txt");
        let mut pt_file = std::fs::File::options()
            .create(true)
            .write(true)
            .open("plaintext.txt")
            .expect("Failed to open plaintext.txt");
        write!(pt_file, "{}", plain_message).expect("Failed to write plaintext.txt");
        let mut ct_file = std::fs::File::options()
            .create(true)
            .write(true)
            .open("ciphertext.txt")
            .expect("Failed to open ciphertext.txt");
        write!(ct_file, "{}", &ct).expect("Failed to write ciphertext.txt");
    }

    fn execute_as_cli(cmd: Command) {
        match cmd {
            Command::Generate => println!(
                "{}",
                hex::encode(Self::generate_key(rand::thread_rng()).as_slice())
            ),
            Command::Encrypt(bytes, key) => {
                let mut cipher = key.map(Self::from_file).unwrap_or_default();
                let ct = cipher.encrypt_message(rand::thread_rng(), &bytes);
                println!("{}", hex::encode(ct));
            }
            Command::Decrypt(bytes, None) if bytes == Self::challenge_cipher_bytes() => {
                println!("cheater: it is forbidden to decrypt the challenge ciphertext");
            }
            Command::Decrypt(bytes, key) => {
                let mut cipher = key.map(Self::from_file).unwrap_or_default();
                let pt = cipher
                    .decrypt_message(&bytes)
                    .expect("Failed to decrypt given hex");
                println!(
                    "{}",
                    String::from_utf8(pt)
                        .expect("Failed to encode decrypted bytes to valid UTF-8 string")
                );
            }
        }
    }
}
