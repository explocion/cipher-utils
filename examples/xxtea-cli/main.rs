pub mod block;
pub mod cipher;

use crate::cipher::*;
use cipher_utils::{cli::*, oracle::CipherOracle};

fn main() {
    let args: Command = Cli::parse().into();
    CorrectedBlockTea::<byteorder::LE>::execute_as_cli(args);
}
