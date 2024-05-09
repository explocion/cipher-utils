use crate::bytes::Bytes;
use crate::cipher::{rand_core::CryptoRngCore, Key, KeyInit};
use crate::cli::Command;

use base64::prelude::*;
use std::{error::Error, fs, path::Path};

#[derive(Debug, Clone)]
pub struct Secret<T: DecryptBytes> {
    pub key: Key<T>,
    pub encrypted_message: Bytes,
}

impl<T: DecryptBytes> Secret<T> {
    pub fn secret_message(&self) -> String {
        let message = T::decrypt_bytes(&self.key, self.encrypted_message.clone()).unwrap();
        String::from_utf8(message.into()).unwrap()
    }
}

pub trait EncryptBytes: KeyInit {
    fn encrypt_bytes(key: &Key<Self>, message: Bytes) -> Bytes;
}

pub trait DecryptBytes: KeyInit {
    type DecryptError: Error;
    fn decrypt_bytes(key: &Key<Self>, message: Bytes) -> Result<Bytes, Self::DecryptError>;
}

pub trait ChallengeCipher: EncryptBytes + DecryptBytes {
    fn secret() -> Secret<Self>;

    fn execute(cmd: Command, rng: impl CryptoRngCore) {
        match cmd {
            Command::Generate => {
                println!("{}", BASE64_URL_SAFE.encode(Self::generate_key(rng)))
            }
            Command::Encrypt {
                secret_message,
                key: path,
            } => {
                let key = path
                    .map(|p| fs::read_to_string(AsRef::<Path>::as_ref(&p)).unwrap())
                    .map(|k| Key::<Self>::clone_from_slice(&BASE64_URL_SAFE.decode(k).unwrap()))
                    .unwrap_or(Self::secret().key);
                let encrypted_message = Self::encrypt_bytes(&key, secret_message.clone());
                println!("{}", BASE64_URL_SAFE.encode(encrypted_message));
            }
            Command::Decrypt {
                encrypted_message,
                key: None,
            } if encrypted_message == Self::secret().encrypted_message => {
                println!("cheater: it is forbidden to decrypt the challenge ciphertext");
            }
            Command::Decrypt {
                encrypted_message,
                key: path,
            } => {
                let key = path
                    .map(|p| fs::read_to_string(AsRef::<Path>::as_ref(&p)).unwrap())
                    .map(|k| Key::<Self>::clone_from_slice(&BASE64_URL_SAFE.decode(k).unwrap()))
                    .unwrap_or(Self::secret().key);
                let secret_message = Self::decrypt_bytes(&key, encrypted_message.clone()).unwrap();
                let secret_message = String::from_utf8(secret_message.into()).unwrap();
                crate::cli::parse_message(&secret_message).unwrap();
                println!("{}", secret_message);
            }
        }
    }
}
