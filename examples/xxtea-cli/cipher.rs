use cipher::block_padding::Pkcs7;
use cipher::generic_array::GenericArray;
use cipher::rand_core::{CryptoRng, RngCore};
use cipher::typenum::{U16, U4};
use cipher::{BlockSizeUser, KeyInit};

use byteorder::ByteOrder;
use cipher_utils::{oracle::*, *};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::block::*;

pub type Key<T> = Block<T>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CorrectedBlockTea<T: ByteOrder> {
    key: Key<T>,
}

impl<'a, T: ByteOrder> From<&'a CorrectedBlockTea<T>> for GenericArray<u8, U16> {
    fn from(value: &'a CorrectedBlockTea<T>) -> Self {
        Self::from(&value.key)
    }
}

impl<T: ByteOrder> KeyInit for CorrectedBlockTea<T> {
    #[inline]
    fn new(key: &cipher::Key<Self>) -> Self {
        Self {
            key: Block::from(key),
        }
    }
}

impl<T: ByteOrder> Default for CorrectedBlockTea<T> {
    #[inline(always)]
    fn default() -> Self {
        let salted_key = hex_literal::hex!("727ee5172f09ca1f12c2f9f02666ecd7");
        let salt = hex_literal::hex!("3044360ea4c415557ecc6cea8c657890");
        Self {
            key: Block::from(&GenericArray::from_iter(
                salted_key.iter().zip(salt.iter()).map(|(a, b)| a ^ b),
            )),
        }
    }
}

impl_cipher_from_hex!(<T: ByteOrder> CorrectedBlockTea, U);

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
        let keys: &GenericArray<u32, U4> = &self.key.block;
        let mut sum = 0u32;
        let mut last = words_block.block[3];
        for _ in 0..(Self::rounds()) {
            sum += Self::DELTA;
            let e = ((sum >> 2) & 3) as usize;
            for i in 0..3 {
                let current = words_block.block[i + 1];
                let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                    ^ ((sum ^ current) + (keys[(i & 3usize) ^ e] ^ last));
                words_block.block[i] = words_block.block[i].wrapping_add(mixed);
                last = words_block.block[i];
            }
            let current = words_block.block[0];
            let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                ^ ((sum ^ current) + (keys[((Self::rounds() - 2) & 3usize) ^ e] ^ last));
            words_block.block[3] = words_block.block[3].wrapping_add(mixed);
            last = words_block.block[3];
        }
    }

    #[allow(arithmetic_overflow)]
    pub fn cipher_decrypt(&self, words_block: &mut Block<T>) {
        let keys: &GenericArray<u32, U4> = &self.key.block;
        let mut sum = Self::rounds() as u32 * Self::DELTA;
        let mut current = words_block.block[0];
        for _ in 0..(Self::rounds()) {
            let e = ((sum >> 2) & 3) as usize;
            for i in (1..=3).rev() {
                let last = words_block.block[i - 1];
                let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                    ^ ((sum ^ current) + (keys[(i & 3usize) ^ e] ^ last));
                words_block.block[i] = words_block.block[i].wrapping_sub(mixed);
                current = words_block.block[i];
            }
            let last = words_block.block[3];
            let mixed = ((last >> 5 ^ current << 2) + (current >> 3 ^ last << 4))
                ^ ((sum ^ current) + (keys[e] ^ last));
            words_block.block[0] = words_block.block[0].wrapping_sub(mixed);
            current = words_block.block[0];
            sum -= Self::DELTA;
        }
    }
}

impl_simple_block_cipher!(
    <T: ByteOrder> CorrectedBlockTea, U16, U16, cipher, block,
    encrypt: {
        let mut words_block: Block<T> = Block::from(block.get_in());
        cipher.cipher_encrypt(&mut words_block);
        *block.get_out() = (&words_block).into();
    }
    decrypt: {
        let mut words_block: Block<T> = Block::from(block.get_in());
        cipher.cipher_decrypt(&mut words_block);
        *block.get_out() = (&words_block).into();
    }
);

impl<'a, T: ByteOrder> PaddedEncrypt<'a> for CorrectedBlockTea<T>
where
    T: 'a,
{
    type Encryptor = pcbc::Encryptor<Self>;
}

impl<'a, T: ByteOrder> PaddedDecrypt<'a> for CorrectedBlockTea<T>
where
    T: 'a,
{
    type Decryptor = pcbc::Decryptor<Self>;
}

impl<T: ByteOrder> CipherOracle for CorrectedBlockTea<T> {
    type DecryptError = PaddedDecryptError;

    fn challenge_cipher_text() -> &'static str {
        "e6cee6d671b272611f7fb19333ab3f4b1c9e22f99affa4a7e937622df8bc0acb10f8a011ca4a2a762e348fc9f34483af"
    }

    fn challenge_cipher_bytes() -> &'static [u8] {
        &hex_literal::hex!("e6cee6d671b272611f7fb19333ab3f4b1c9e22f99affa4a7e937622df8bc0acb10f8a011ca4a2a762e348fc9f34483af")
    }

    #[inline]
    fn encrypt_message(&mut self, rng: impl CryptoRng + RngCore, plain_message: &[u8]) -> Vec<u8> {
        self.padded_encrypt_message::<Pkcs7>(rng, plain_message)
    }

    #[inline]
    fn decrypt_message(&mut self, encrypted_message: &[u8]) -> Result<Vec<u8>, Self::DecryptError> {
        self.padded_decrypt_message::<Pkcs7>(encrypted_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt() {
        let plaintext = GenericArray::from(hex_literal::hex!("9d6693d5232456c52d69788aa2c67e1a"));
        let plaintext = Block::<byteorder::LE>::from(&plaintext);
        let cipher = CorrectedBlockTea::generate();
        let mut decrypted = plaintext.clone();
        cipher.cipher_encrypt(&mut decrypted);
        cipher.cipher_decrypt(&mut decrypted);
        assert_eq!(plaintext.block, decrypted.block);
    }
}
