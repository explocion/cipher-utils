use crate::bytes::Bytes;

use base64::prelude::*;
use clap::{Parser, Subcommand};
use regex::Regex;
use std::{error::Error, fmt, path::PathBuf};

#[derive(Debug, Default)]
pub struct IllegalCharacter;

impl IllegalCharacter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Display for IllegalCharacter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal character")
    }
}

impl Error for IllegalCharacter {}

pub fn parse_message(message: &str) -> Result<Bytes, IllegalCharacter> {
    use once_cell::sync::Lazy;
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-zA-Z\,\.\;\?\!\(\)]+$").unwrap());

    RE.is_match(message)
        .then_some(message)
        .map(|message| message.as_bytes().to_vec().into())
        .ok_or(IllegalCharacter::new())
}

pub fn parse_base64(value: &str) -> Result<Bytes, base64::DecodeError> {
    BASE64_URL_SAFE.decode(value).map(|bytes| bytes.into())
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    Generate,
    Encrypt {
        #[arg(value_parser = parse_message)]
        secret_message: Bytes,
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    Decrypt {
        #[arg(value_parser = parse_base64)]
        encrypted_message: Bytes,
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq, Eq, Parser)]
#[command(author, version, about, long_about)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

pub fn command() -> Command {
    Cli::parse().command
}
