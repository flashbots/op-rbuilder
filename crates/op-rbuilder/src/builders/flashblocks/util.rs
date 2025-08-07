use rollup_boost::FlashblocksPayloadV1;
use serde_json::Value;

/// Calculates the approximate number of bytes used by a FlashblocksPayloadV1
pub fn calculate_flashblock_byte_size(fb_payload: &FlashblocksPayloadV1) -> usize {
    // Start with PayloadId (8 bytes) + Index (8 bytes)
    let mut total_bytes = 16;

    // Base (if present)
    if let Some(ref base) = fb_payload.base {
        // Sum of:
        // * 32 parent_beacon_block_root
        // * 32 parent_hash
        // * 32 prev_randao
        // * 20 fee_recipient
        // * 8 block_number
        // * 8 gas_limit
        // * 8 timestamp
        // * 32 base_fee_per_gas
        total_bytes += 172;

        // Bytes field - variable length
        total_bytes += base.extra_data.len();
    }

    // Diff, sum of:
    // * 32 state_root
    // * 32 receipts_root
    // * 32 block_hash
    // * 32 withdrawals_root
    // * 256 logs_bloom
    // * 8 gas_used
    total_bytes += 392;
    // Transactions - sum of all transaction bytes
    for tx in &fb_payload.diff.transactions {
        total_bytes += tx.len();
    }
    // Withdrawals - each withdrawal has fixed fields:
    // index (8) + validator_index (8) + address (20) + amount (8)
    total_bytes += 44 * fb_payload.diff.withdrawals.len();

    // Metadata
    total_bytes += estimate_json_value_size(&fb_payload.metadata);

    total_bytes
}

/// Traverse the serde_json::Value to estimate its size without serializing it
fn estimate_json_value_size(value: &Value) -> usize {
    match value {
        Value::Null => 4,    // "null"
        Value::Bool(_) => 5, // "true" or "false"
        Value::Number(n) => n.to_string().len(),
        Value::String(s) => s.len() + 2, // +2 for quotes
        Value::Array(arr) => {
            let mut size = 2; // brackets []
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    size += 1; // comma
                }
                size += estimate_json_value_size(v);
            }
            size
        }
        Value::Object(map) => {
            let mut size = 2; // braces {}
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    size += 1; // comma
                }
                size += k.len() + 3; // key + quotes + colon
                size += estimate_json_value_size(v);
            }
            size
        }
    }
}
