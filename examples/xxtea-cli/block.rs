use cipher::generic_array::GenericArray;
use cipher::typenum::{U16, U4};
use hex::FromHex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use byteorder::ByteOrder;
use std::cmp::Ordering;
use std::marker::PhantomData;

use cipher_utils::FromBytesError;

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Block<T: ByteOrder> {
    pub block: GenericArray<u32, U4>,
    _endianess: PhantomData<T>,
}

impl<'a, T: ByteOrder> From<&'a GenericArray<u8, U16>> for Block<T> {
    #[inline]
    fn from(value: &'a GenericArray<u8, U16>) -> Self {
        let mut block = Self::default();
        T::read_u32_into(value.as_slice(), &mut block.block);
        block
    }
}

impl<'a, T: ByteOrder> From<&'a Block<T>> for GenericArray<u8, U16> {
    fn from(value: &'a Block<T>) -> Self {
        let mut bytes = GenericArray::default();
        T::write_u32_into(&value.block, bytes.as_mut_slice());
        bytes
    }
}

impl<T: ByteOrder> FromHex for Block<T> {
    type Error = FromBytesError;

    fn from_hex<U: AsRef<[u8]>>(hex: U) -> Result<Self, Self::Error> {
        let bytes = hex.as_ref();
        match bytes.len().cmp(&4) {
            Ordering::Less => Err(Self::Error::NoEnoughBytes),
            Ordering::Equal => Ok(Self::from(GenericArray::from_slice(bytes))),
            Ordering::Greater => Err(Self::Error::TooMuchBytes),
        }
    }
}
