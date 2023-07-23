pub use clap::Parser;

use clap::Args;
use regex::Regex;
use std::{fmt, path::PathBuf};

#[derive(Debug, Clone, PartialEq)]
enum ParseCharacterError {
    IllegalCharacter,
    RegexFault(regex::Error),
}

impl fmt::Display for ParseCharacterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalCharacter => {
                write!(f, "illegal character detected in the argument value")
            }
            Self::RegexFault(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ParseCharacterError {}

type Blob = Vec<u8>;

fn parse_characters(value: &str) -> Result<Blob, ParseCharacterError> {
    let re = Regex::new(r"^[0-9a-zA-Z\,\.\;\?\!\(\)]+$")
        .map_err(|e| ParseCharacterError::RegexFault(e))?;
    if re.is_match(value) {
        Ok(value.as_bytes().to_vec())
    } else {
        Err(ParseCharacterError::IllegalCharacter)
    }
}

#[inline]
fn parse_hex(value: &str) -> Result<Blob, hex::FromHexError> {
    hex::decode(value)
}

#[derive(Debug, PartialEq, Eq, Clone, Args)]
#[group(required = true, multiple = false)]
struct Action {
    /// generate key for the cipher
    #[arg(short, long)]
    generate: bool,

    /// encrypt plaintext with cipher, optionally with specified key
    #[arg(short, long, value_parser = parse_characters, group = "cipher")]
    encrypt: Option<Blob>,

    /// decrypt ciphertext with cipher, optionally with specified key
    #[arg(short, long, value_parser = parse_hex, group = "cipher")]
    decrypt: Option<Blob>,
}

#[derive(Debug, PartialEq, Eq, Clone, Parser)]
#[command(author, version, about, long_about)]
pub struct Cli {
    #[command(flatten)]
    action: Action,

    /// optionally specify the key, or default key would be used
    /// key must be specified when decrypting challenge ciphertext
    #[arg(short, long, requires = "cipher")]
    key: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Command {
    Generate,
    Encrypt(Blob, Option<PathBuf>),
    Decrypt(Blob, Option<PathBuf>),
}

impl From<Cli> for Command {
    fn from(value: Cli) -> Self {
        match value.action {
            Action {
                generate: true,
                encrypt: _,
                decrypt: _,
            } => Command::Generate,
            Action {
                generate: _,
                encrypt: Some(m),
                decrypt: _,
            } => Command::Encrypt(m, value.key),
            Action {
                generate: _,
                encrypt: _,
                decrypt: Some(c),
            } => Command::Decrypt(c, value.key),
            _ => panic!("Should be impossible, but Clap parser failed!"),
        }
    }
}
