use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bundle {
    pub transactions: Vec<Bytes>,
    pub block_number_max: Option<u64>,
}

pub const MAX_BLOCK_RANGE_BLOCKS: u64 = 10;
