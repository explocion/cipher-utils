use crate::bytes::{Bytes, BytesMut};
use crate::cipher::{rand_core::CryptoRngCore, Key};
use crate::traits::{DecryptBytes, EncryptBytes};

pub fn generate_plaintext<R: CryptoRngCore>(rng: &mut R) -> Bytes {
    let mut plaintext = {
        let mut len = [0u8; 2];
        rng.fill_bytes(&mut len);
        let len = u16::from_ne_bytes(len) as usize;
        BytesMut::zeroed(len)
    };
    rng.fill_bytes(&mut plaintext);
    plaintext.into()
}

pub fn check_composition_identity<T: EncryptBytes + DecryptBytes>(mut rng: impl CryptoRngCore) {
    let plaintext = generate_plaintext(&mut rng);
    let key = T::generate_key(rng);
    let ciphertext = T::encrypt_bytes(&key, plaintext.clone());
    assert_eq!(plaintext, T::decrypt_bytes(&key, ciphertext).unwrap());
}

pub fn check_key_generation_and_identity<T: EncryptBytes + DecryptBytes, R: CryptoRngCore>(
    mut rng: impl FnMut() -> R,
    rounds: usize,
) {
    use std::collections::HashSet;

    let keys: HashSet<Key<T>> = HashSet::new();
    for _ in 0..rounds {
        let key = T::generate_key(rng());
        assert_eq!(false, keys.contains(&key));
        check_composition_identity::<T>(rng());
    }
}
