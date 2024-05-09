use cipher_utils::*;

use bytes::Bytes;
use cipher::*;
use traits::*;

pub struct Caesar(u8);

impl KeyInit for Caesar {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self(key[0].clone())
    }
}

impl_simple_block_cipher!(Caesar, typenum::U1, typenum::U1, caesar, block,
encrypt: {
    let Caesar(shift) = caesar;
    let shifted = block.get_in().first().unwrap().wrapping_add(*shift);
    block.get_out().fill(shifted);
}
decrypt: {
    let Caesar(shift) = caesar;
    let shifted = block.get_in().first().unwrap().wrapping_sub(*shift);
    block.get_out().fill(shifted);
});

impl EncryptBytes for Caesar {
    fn encrypt_bytes(key: &Key<Self>, plaintext: Bytes) -> Bytes {
        let caesar = Caesar::new(key);
        caesar
            .encrypt_padded_vec::<block_padding::NoPadding>(&plaintext)
            .into()
    }
}

impl DecryptBytes for Caesar {
    type DecryptError = block_padding::UnpadError;

    fn decrypt_bytes(key: &Key<Self>, plaintext: Bytes) -> Result<Bytes, Self::DecryptError> {
        let caesar = Caesar::new(key);
        caesar
            .decrypt_padded_vec::<block_padding::NoPadding>(&plaintext)
            .map(|v| v.into())
    }
}

impl ChallengeCipher for Caesar {
    fn secret() -> Secret<Self> {
        let key = generic_array::arr![u8; 42];
        Secret {
            key,
            encrypted_message: Self::encrypt_bytes(&key, b"manuel".to_vec().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use test::*;

    #[test]
    fn composition_id() {
        for _ in 0..10 {
            check_composition_identity::<Caesar, _>(thread_rng);
        }
    }

    #[test]
    fn key_generation_composition_id() {
        check_key_generation_and_identity::<Caesar, _>(thread_rng, 20);
    }
}

fn main() {
    let cmd = cli::command();
    Caesar::execute(cmd, rand::thread_rng());
}
