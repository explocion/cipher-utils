# `cipher-utils` for ECE475 Challenge 2

## Examples

In the `examples` folder, you can find `xxtea-cli`, which is a full implementation of Corrected Block TEA. The example consists of 2 parts: a file named `bootstrap.rs`, which generates the default key, plaintext and ciphertext for the challenge; and other files that implements the specified command line interface of the challenge.

## CI/CD via Drone

The repository is designed to have CI/CD with Drone, where the following test is run for each commit.

```bash
cargo build --release
cargo test --release
./test.py xxtea-cli
```
