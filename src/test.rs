use crate::bytes::{Bytes, BytesMut};
use crate::cipher::{rand_core::CryptoRngCore, Key};
use crate::traits::{DecryptBytes, EncryptBytes};

pub fn random_message<R: CryptoRngCore>(mut rng: impl FnMut() -> R, len: usize) -> Bytes {
    let mut message = BytesMut::zeroed(len);
    rng().fill_bytes(&mut message);
    message.into()
}

pub fn check_composition_identity<T: EncryptBytes + DecryptBytes, R: CryptoRngCore>(
    mut rng: impl FnMut() -> R,
) {
    let key = T::generate_key(rng());
    let message = random_message(rng, 100);
    let encrypted_message = T::encrypt_bytes(&key, message.clone());
    assert_eq!(message, T::decrypt_bytes(&key, encrypted_message).unwrap());
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
        check_composition_identity::<T, _>(&mut rng);
    }
}
