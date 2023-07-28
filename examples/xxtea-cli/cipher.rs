use cipher::block_padding::Pkcs7;
use cipher::generic_array::GenericArray;
use cipher::rand_core::{CryptoRng, RngCore};
use cipher::typenum::{U16, U4};
use cipher::{BlockSizeUser, KeyInit};

use cipher_utils::FromBytesError;
use hex::FromHex;
use hex_literal as _;

use byteorder::ByteOrder;
use include_crypt::include_crypt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::block::*;
use cipher_utils::{oracle::*, *};

pub type Key<T> = Block<T>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CorrectedBlockTea<T: ByteOrder> {
    key: Key<T>,
}

impl<T: ByteOrder> FromHex for CorrectedBlockTea<T> {
    type Error = FromBytesError;

    #[inline]
    fn from_hex<U: AsRef<[u8]>>(hex: U) -> Result<Self, Self::Error> {
        Ok(Self {
            key: Block::from_hex(hex)?,
        })
    }
}

impl<T: ByteOrder> KeyInit for CorrectedBlockTea<T> {
    #[inline]
    fn new(key: &cipher::Key<Self>) -> Self {
        Self {
            key: Block::from_hex(key.as_slice()).unwrap(),
        }
    }
}

impl<T: ByteOrder> DefaultKey for CorrectedBlockTea<T> {
    #[inline(always)]
    fn default_key() -> cipher::Key<Self> {
        let encrypted = include_crypt!(AES, "examples/xxtea-cli/key.txt");
        let hex = encrypted
            .decrypt_str()
            .expect("invalid UTF-8 string from default key");
        let bytes = hex::decode(hex).expect("failed to decode key hex to bytes");
        cipher::Key::<Self>::clone_from_slice(&bytes)
    }
}

impl<T: ByteOrder> CorrectedBlockTea<T> {
    pub const DELTA: u32 = 0x9e3779b9u32;

    #[inline]
    pub fn block_size_in_words() -> usize {
        Self::block_size() >> 2
    }

    #[inline]
    pub fn rounds() -> usize {
        8 + 52 / Self::block_size_in_words()
    }

    #[allow(arithmetic_overflow)]
    pub fn cipher_encrypt(&self, words_block: &mut Block<T>) {
        let keys: &GenericArray<u32, U4> = &self.key.words;
        let mut sum = 0u32;
        let mut last = words_block.words[3];
        for _ in 0..(Self::rounds()) {
            sum += Self::DELTA;
            let e = ((sum >> 2) & 3) as usize;
            for i in 0..3 {
                let current = words_block.words[i + 1];
                let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                    ^ ((sum ^ current) + (keys[(i & 3usize) ^ e] ^ last));
                words_block.words[i] = words_block.words[i].wrapping_add(mixed);
                last = words_block.words[i];
            }
            let current = words_block.words[0];
            let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                ^ ((sum ^ current) + (keys[((Self::rounds() - 2) & 3usize) ^ e] ^ last));
            words_block.words[3] = words_block.words[3].wrapping_add(mixed);
            last = words_block.words[3];
        }
    }

    #[allow(arithmetic_overflow)]
    pub fn cipher_decrypt(&self, words_block: &mut Block<T>) {
        let keys: &GenericArray<u32, U4> = &self.key.words;
        let mut sum = Self::rounds() as u32 * Self::DELTA;
        let mut current = words_block.words[0];
        for _ in 0..(Self::rounds()) {
            let e = ((sum >> 2) & 3) as usize;
            for i in (1..=3).rev() {
                let last = words_block.words[i - 1];
                let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                    ^ ((sum ^ current) + (keys[(i & 3usize) ^ e] ^ last));
                words_block.words[i] = words_block.words[i].wrapping_sub(mixed);
                current = words_block.words[i];
            }
            let last = words_block.words[3];
            let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                ^ ((sum ^ current) + (keys[e] ^ last));
            words_block.words[0] = words_block.words[0].wrapping_sub(mixed);
            current = words_block.words[0];
            sum -= Self::DELTA;
        }
    }
}

impl_simple_block_cipher!(
    <T: ByteOrder> CorrectedBlockTea, U16, U16, cipher, block,
    encrypt: {
        let mut words_block: Block<T> = Block::from_hex(block.get_in()).unwrap();
        cipher.cipher_encrypt(&mut words_block);
        *block.get_out() = words_block.to_bytes();
    }
    decrypt: {
        let mut words_block: Block<T> = Block::from_hex(block.get_in()).unwrap();
        cipher.cipher_decrypt(&mut words_block);
        *block.get_out() = words_block.to_bytes();
    }
);

impl<T: ByteOrder> PaddedEncrypt for CorrectedBlockTea<T> {
    type Encryptor = pcbc::Encryptor<Self>;
}

impl<T: ByteOrder> PaddedDecrypt for CorrectedBlockTea<T> {
    type Decryptor = pcbc::Decryptor<Self>;
}

impl<T: ByteOrder> CipherOracle for CorrectedBlockTea<T> {
    type DecryptError = PaddedDecryptError;

    #[inline(always)]
    fn challenge_cipher_text() -> &'static str {
        include_str!("ciphertext.txt")
    }

    #[inline(always)]
    fn challenge_cipher_bytes() -> &'static [u8] {
        const CIPHER_TEXT: &'static str = include_str!("ciphertext.txt");
        const STRING_BYTES: &[&'static [u8]] = &[CIPHER_TEXT.as_bytes()];
        const LEN: usize = hex_literal::len(STRING_BYTES);
        const BYTES: [u8; LEN] = hex_literal::decode(STRING_BYTES);
        &BYTES
    }

    #[inline]
    fn encrypt(
        key: &cipher::Key<Self>,
        rng: impl CryptoRng + RngCore,
        plaintext: &[u8],
    ) -> Vec<u8> {
        Self::padded_encrypt::<Pkcs7>(key, rng, plaintext)
    }

    #[inline]
    fn decrypt(key: &cipher::Key<Self>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::DecryptError> {
        Self::padded_decrypt::<Pkcs7>(key, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn encrypt_then_decrypt() {
        let plaintext = GenericArray::from(hex!("9d6693d5232456c52d69788aa2c67e1a"));
        let plaintext = Block::<byteorder::LE>::from_hex(plaintext.as_slice()).unwrap();
        let cipher = CorrectedBlockTea::new(&CorrectedBlockTea::<byteorder::LE>::generate_key(
            rand::thread_rng(),
        ));
        let mut decrypted = plaintext.clone();
        cipher.cipher_encrypt(&mut decrypted);
        cipher.cipher_decrypt(&mut decrypted);
        assert_eq!(plaintext.words, decrypted.words);
    }
}
