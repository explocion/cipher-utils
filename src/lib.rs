pub use bytes;
pub use cipher;
pub use rand;

pub mod cli;
pub mod traits;

#[cfg(feature = "dev")]
pub mod test;

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
                f.write_str(stringify!($cipher))
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
