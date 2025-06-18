use rblib::{BlockContext, Optimism};
use reth_node_api::PayloadBuilderError;
use reth_optimism_node::OpBuiltPayload;

pub fn build_empty_payload(
    block: &BlockContext<Optimism>,
) -> Result<OpBuiltPayload, PayloadBuilderError> {
    let mut checkpoint = block.start();

    // apply sequencer transactions
    for tx in block.attributes().transactions.iter() {
        checkpoint = checkpoint
            .apply(tx.value().clone())
            .map_err(PayloadBuilderError::other)?;
    }

    assert_eq!(checkpoint.depth(), block.attributes().transactions.len());

    // produce a payload with no user or builder transactions
    checkpoint.build()
}
