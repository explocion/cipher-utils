pub mod cli;
pub mod oracle;

use core::fmt;

pub use cipher;
pub use hex;

use cipher::block_padding::{RawPadding, UnpadError};
use cipher::generic_array::GenericArray;
use cipher::rand_core::{CryptoRng, RngCore};
use cipher::{
    BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, Iv, IvSizeUser, Key, KeyInit,
    KeyIvInit,
};

#[derive(Clone, Debug)]
pub enum FromBytesError {
    NoEnoughBytes,
    TooMuchBytes,
}

impl fmt::Display for FromBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEnoughBytes => write!(f, "no enough bytes to construct cipher"),
            Self::TooMuchBytes => write!(f, "more bytes than needed to construct cipher"),
        }
    }
}

#[cfg(not(no_std))]
impl std::error::Error for FromBytesError {}

#[macro_export]
macro_rules! impl_cipher_from_hex {
    (
        <$($N:ident$(:$b0:ident$(+$b:ident)*)?),*>
        $cipher:ident, $generic:ident
    ) => {
        impl<$($N$(:$b0$(+$b)*)?),*> hex::FromHex for $cipher<$($N),*> {
            type Error = $crate::FromBytesError;

            fn from_hex<$generic: AsRef<[u8]>>(hex: $generic) -> Result<Self, Self::Error> {
                use core::cmp::Ordering;
                use cipher::{generic_array::GenericArray, typenum::Unsigned};
                let key_size = <<Self as cipher::KeySizeUser>::KeySize as Unsigned>::to_usize();
                let bytes = hex.as_ref();
                match bytes.len().cmp(&key_size) {
                    Ordering::Less => Err(Self::Error::NoEnoughBytes),
                    Ordering::Equal => Ok(Self::new(GenericArray::from_slice(bytes))),
                    Ordering::Greater => Err(Self::Error::TooMuchBytes),
                }
            }
        }
    };
    ($cipher:ident) => {
        impl_cipher_from_hex!(<> $cipher, $generic);
    };
}

#[derive(Debug, Clone)]
pub enum PaddedDecryptError {
    LessThanOneBlock,
    UnpadError(UnpadError),
}

impl fmt::Display for PaddedDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LessThanOneBlock => write!(f, "cipher text less than one block"),
            Self::UnpadError(e) => e.fmt(f),
        }
    }
}

#[cfg(not(no_std))]
impl std::error::Error for PaddedDecryptError {}

pub trait PaddedEncrypt<'a>: KeyInit + BlockEncryptMut + BlockCipher
where
    Self: 'a,
    Key<Self::Encryptor>: From<&'a Self>,
{
    type Encryptor: KeyIvInit + BlockEncryptMut;

    fn padded_encrypt_message<P: RawPadding>(
        &'a mut self,
        rng: impl CryptoRng + RngCore,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let ct_len = (plaintext.len() / Self::block_size() + 2) * Self::block_size();
        let mut buf = Vec::with_capacity(ct_len);
        buf.resize(ct_len, 0);
        let iv = Self::Encryptor::generate_iv(rng);
        self.encrypt_block_b2b_mut(
            GenericArray::from_slice(iv.as_slice()),
            GenericArray::from_mut_slice(&mut buf[..Self::block_size()]),
        );
        let encryptor = Self::Encryptor::new(&Key::<Self::Encryptor>::from(self), &iv);
        encryptor
            .encrypt_padded_b2b_mut::<P>(&plaintext, &mut buf[Self::block_size()..])
            .expect("Failed to pad the input plain text");
        buf
    }
}

pub trait PaddedDecrypt<'a>: KeyInit + BlockDecryptMut + BlockCipher
where
    Self: 'a,
    Key<Self::Decryptor>: From<&'a Self>,
{
    type Decryptor: KeyIvInit + BlockDecryptMut;

    fn padded_decrypt_message<P: RawPadding>(
        &'a mut self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PaddedDecryptError> {
        if ciphertext.len() < Self::block_size() {
            Err(PaddedDecryptError::LessThanOneBlock)
        } else {
            let (iv, ciphertext) = ciphertext.split_at(Self::Decryptor::block_size());
            let mut decrypted_iv: Iv<Self::Decryptor> =
                GenericArray::<u8, <Self::Decryptor as IvSizeUser>::IvSize>::default();
            self.decrypt_block_b2b_mut(
                GenericArray::from_slice(iv),
                GenericArray::from_mut_slice(decrypted_iv.as_mut_slice()),
            );
            let decryptor =
                Self::Decryptor::new(&Key::<Self::Decryptor>::from(self), &decrypted_iv);
            decryptor
                .decrypt_padded_vec_mut::<P>(ciphertext)
                .map_err(|e| PaddedDecryptError::UnpadError(e))
        }
    }
}

#[macro_export]
macro_rules! impl_simple_block_cipher {
    (
        <$($N:ident$(:$b0:ident$(+$b:ident)*)?),*>
        $cipher:ident, $key_size:ty, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        impl<$($N$(:$b0$(+$b)*)?),*> cipher::AlgorithmName for $cipher<$($N),*> {
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!($cipher ))
            }
        }

        impl<$($N$(:$b0$(+$b)*)?),*> cipher::KeySizeUser for $cipher<$($N),*> {
            type KeySize = $key_size;
        }

        cipher::impl_simple_block_encdec!(<$($N$(:$b0$(+$b)*)?),*> $cipher, $block_size, $state, $block, encrypt: $enc_block decrypt: $dec_block);

        impl<$($N$(:$b0$(+$b)*)?),*> cipher::BlockCipher for $cipher<$($N),*> {}
    };
    (
        $cipher:ident, $key_size:ty, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        impl_simple_block_cipher!(<> $cipher, $key_size, $block_size, $state, $block, encrypt: $enc_block decrypt: $dec_block);
    };
}
