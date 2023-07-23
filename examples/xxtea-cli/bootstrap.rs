pub mod block;
pub mod cipher;

use crate::cipher::*;
use cipher_utils::oracle::CipherOracle;

fn main() {
    CorrectedBlockTea::<byteorder::LE>::bootstrap("2is(cons.(cons.(nil;)))!");
}
