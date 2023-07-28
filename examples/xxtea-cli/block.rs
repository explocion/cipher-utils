use cipher::generic_array::GenericArray;
use cipher::typenum::{U16, U4};

use byteorder::ByteOrder;
use std::{cmp::Ordering, marker::PhantomData};
use zeroize::{Zeroize, ZeroizeOnDrop};

use cipher_utils::FromBytesError;
use hex::FromHex;

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Block<T: ByteOrder> {
    pub words: GenericArray<u32, U4>,
    _endianess: PhantomData<T>,
}

impl<T: ByteOrder> FromHex for Block<T> {
    type Error = FromBytesError;

    fn from_hex<U: AsRef<[u8]>>(hex: U) -> Result<Self, Self::Error> {
        let bytes = hex.as_ref();
        match bytes.len().cmp(&16) {
            Ordering::Less => Err(Self::Error::NoEnoughBytes),
            Ordering::Equal => Ok({
                let mut words = GenericArray::default();
                T::read_u32_into(bytes, words.as_mut_slice());
                Self {
                    words,
                    _endianess: PhantomData,
                }
            }),
            Ordering::Greater => Err(Self::Error::TooMuchBytes),
        }
    }
}

impl<T: ByteOrder> Block<T> {
    pub fn to_bytes(&self) -> GenericArray<u8, U16> {
        let mut bytes = GenericArray::default();
        T::write_u32_into(self.words.as_slice(), bytes.as_mut_slice());
        bytes
    }
}
