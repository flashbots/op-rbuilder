use rollup_boost::FlashblocksPayloadV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub(super) enum Message {
    FlashblocksPayloadV1(FlashblocksPayloadV1),
}

impl p2p::Message for Message {}

impl From<FlashblocksPayloadV1> for Message {
    fn from(value: FlashblocksPayloadV1) -> Self {
        Message::FlashblocksPayloadV1(value)
    }
}
