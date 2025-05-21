use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bundle {
    pub transaction: Bytes,
    pub block_number_min: Option<u64>,
    pub block_number_max: Option<u64>,
}
