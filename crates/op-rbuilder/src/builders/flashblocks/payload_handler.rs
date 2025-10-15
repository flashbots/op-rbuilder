use crate::{
    builders::flashblocks::{ctx::OpPayloadSyncerCtx, p2p::Message, payload::ExtraExecutionInfo},
    gas_limiter::{AddressGasLimiter, args::GasLimiterArgs},
    metrics::OpRBuilderMetrics,
    primitives::reth::ExecutionInfo,
    traits::ClientBounds,
};
use alloy_evm::eth::receipt_builder::ReceiptBuilderCtx;
use alloy_primitives::B64;
use eyre::{WrapErr as _, bail};
use futures::stream::FuturesUnordered;
use futures_util::StreamExt as _;
use op_alloy_consensus::OpTxEnvelope;
use reth::revm::{State, database::StateProviderDatabase};
use reth_basic_payload_builder::PayloadConfig;
use reth_evm::FromRecoveredTx;
use reth_node_builder::Events;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_node::{OpEngineTypes, OpPayloadBuilderAttributes};
use reth_optimism_payload_builder::OpBuiltPayload;
use reth_optimism_primitives::{OpReceipt, OpTransactionSigned};
use rollup_boost::FlashblocksPayloadV1;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Handles newly built or received flashblock payloads.
///
/// In the case of a payload built by this node, it is broadcast to peers and an event is sent to the payload builder.
/// In the case of a payload received from a peer, it is executed and if successful, an event is sent to the payload builder.
pub(crate) struct PayloadHandler<Client> {
    // receives new payloads built by this builder.
    built_rx: mpsc::Receiver<OpBuiltPayload>,
    // receives incoming p2p messages from peers.
    p2p_rx: mpsc::Receiver<Message>,
    // outgoing p2p channel to broadcast new payloads to peers.
    p2p_tx: mpsc::Sender<Message>,
    // sends a `Events::BuiltPayload` to the reth payload builder when a new payload is received.
    payload_events_handle: tokio::sync::broadcast::Sender<Events<OpEngineTypes>>,
    // context required for execution of blocks during syncing
    ctx: OpPayloadSyncerCtx,
    metrics: Arc<OpRBuilderMetrics>,
    gas_limiter_config: GasLimiterArgs,
    client: Client,
    cancel: tokio_util::sync::CancellationToken,
}

impl<Client> PayloadHandler<Client>
where
    Client: ClientBounds + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        built_rx: mpsc::Receiver<OpBuiltPayload>,
        p2p_rx: mpsc::Receiver<Message>,
        p2p_tx: mpsc::Sender<Message>,
        payload_events_handle: tokio::sync::broadcast::Sender<Events<OpEngineTypes>>,
        ctx: OpPayloadSyncerCtx,
        metrics: Arc<OpRBuilderMetrics>,
        gas_limiter_config: GasLimiterArgs,
        client: Client,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            built_rx,
            p2p_rx,
            p2p_tx,
            payload_events_handle,
            ctx,
            metrics,
            gas_limiter_config,
            client,
            cancel,
        }
    }

    pub(crate) async fn run(self) {
        let Self {
            mut built_rx,
            mut p2p_rx,
            p2p_tx,
            payload_events_handle,
            ctx,
            metrics,
            gas_limiter_config,
            client,
            cancel,
        } = self;

        tracing::debug!("flashblocks payload handler started");

        let mut execute_flashblock_futures = FuturesUnordered::new();

        loop {
            tokio::select! {
                Some(payload) = built_rx.recv() => {
                    let _  = payload_events_handle.send(Events::BuiltPayload(payload.clone()));
                    // TODO: only broadcast if `!no_tx_pool`?
                    // ignore error here; if p2p was disabled, the channel will be closed.
                    let _ = p2p_tx.send(payload.into()).await;
                }
                Some(message) = p2p_rx.recv() => {
                    match message {
                        Message::OpBuiltPayload(payload) => {
                            let payload: OpBuiltPayload = payload.into();
                            let handle = tokio::spawn(
                                execute_flashblock(
                                    payload,
                                    ctx.clone(),
                                    client.clone(),
                                    metrics.clone(),
                                    cancel.clone(),
                                    gas_limiter_config.clone(),
                                )
                            );
                            execute_flashblock_futures.push(handle);
                        }
                    }
                }
                Some(res) = execute_flashblock_futures.next() => {
                    match res {
                        Ok(Ok((payload, _))) => {
                            tracing::info!(hash = payload.block().hash().to_string(), block_number = payload.block().header().number, "successfully executed flashblock");
                            let _  = payload_events_handle.send(Events::BuiltPayload(payload));
                        }
                        Ok(Err(e)) => {
                            tracing::error!(error = ?e, "failed to execute flashblock");
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "task panicked while executing flashblock");
                        }
                    }
                }
                else => break,
            }
        }
    }
}

async fn execute_flashblock<Client>(
    payload: OpBuiltPayload,
    ctx: OpPayloadSyncerCtx,
    client: Client,
    metrics: Arc<OpRBuilderMetrics>,
    cancel: tokio_util::sync::CancellationToken,
    gas_limiter_config: GasLimiterArgs,
) -> eyre::Result<(OpBuiltPayload, FlashblocksPayloadV1)>
where
    Client: ClientBounds,
{
    use alloy_consensus::BlockHeader as _;
    use reth::primitives::SealedHeader;
    use reth_evm::{ConfigureEvm as _, execute::BlockBuilder as _};

    tracing::info!(header = ?payload.block().header(), "executing flashblock");

    let mut cached_reads = reth::revm::cached::CachedReads::default();
    let parent_hash = payload.block().sealed_header().parent_hash;
    let parent_header = client
        .header_by_id(parent_hash.into())
        .wrap_err("failed to get parent header")?
        .ok_or_else(|| eyre::eyre!("parent header not found"))?;
    // TODO: can refactor this out probably
    let payload_config = PayloadConfig::new(
        Arc::new(SealedHeader::new(parent_header.clone(), parent_hash)),
        OpPayloadBuilderAttributes::default(),
    );

    let state_provider = client
        .state_by_block_hash(parent_hash)
        .wrap_err("failed to get state for parent hash")?;
    let db = StateProviderDatabase::new(&state_provider);
    let mut state = State::builder()
        .with_database(cached_reads.as_db_mut(db))
        .with_bundle_update()
        .build();

    let chain_spec = client.chain_spec();
    let timestamp = payload.block().header().timestamp();
    let block_env_attributes = OpNextBlockEnvAttributes {
        timestamp,
        suggested_fee_recipient: payload.block().sealed_header().beneficiary,
        prev_randao: payload.block().sealed_header().mix_hash,
        gas_limit: payload.block().sealed_header().gas_limit,
        parent_beacon_block_root: payload.block().sealed_header().parent_beacon_block_root,
        extra_data: payload.block().sealed_header().extra_data.clone(),
    };

    let evm_env = ctx
        .evm_config()
        .next_evm_env(&parent_header, &block_env_attributes)
        .wrap_err("failed to create next evm env")?;

    let address_gas_limiter = AddressGasLimiter::new(gas_limiter_config);
    // TODO: can probably refactor this
    let mut builder_ctx = ctx.into_op_payload_builder_ctx(
        payload_config,
        evm_env.clone(),
        block_env_attributes,
        cancel,
        metrics,
        address_gas_limiter,
    );

    builder_ctx
        .evm_config
        .builder_for_next_block(
            &mut state,
            &builder_ctx.config.parent_header,
            builder_ctx.block_env_attributes.clone(),
        )
        .wrap_err("failed to create evm builder for next block")?
        .apply_pre_execution_changes()
        .wrap_err("failed to apply pre execution changes")?;

    let mut info = ExecutionInfo::with_capacity(payload.block().body().transactions.len());

    let extra_data = payload.block().sealed_header().extra_data.clone();
    if extra_data.len() != 9 {
        tracing::error!(len = extra_data.len(), data = ?extra_data, "invalid extra data length in flashblock");
        eyre::bail!("extra data length should be 9 bytes");
    }

    let eip_1559_parameters: B64 = extra_data[1..9].try_into().unwrap();
    builder_ctx.config.attributes.eip_1559_params = Some(eip_1559_parameters);
    builder_ctx
        .config
        .attributes
        .payload_attributes
        .parent_beacon_block_root = payload.block().sealed_header().parent_beacon_block_root;
    builder_ctx.config.attributes.payload_attributes.timestamp = timestamp;
    builder_ctx.config.attributes.payload_attributes.prev_randao =
        payload.block().sealed_header().mix_hash;

    execute_transactions(
        &mut info,
        &mut state,
        payload.block().body().transactions.clone(),
        payload.block().header().gas_used,
        &builder_ctx.evm_config,
        evm_env,
        builder_ctx.max_gas_per_txn,
        is_canyon_active(&chain_spec, timestamp),
        is_regolith_active(&chain_spec, timestamp),
    )
    .wrap_err("failed to execute best transactions")?;

    let (built_payload, fb_payload) = crate::builders::flashblocks::payload::build_block(
        &mut state,
        &builder_ctx,
        &mut info,
        true, // TODO: do we need this always?
    )
    .wrap_err("failed to build flashblock")?;

    if built_payload.block().hash() != payload.block().hash() {
        tracing::error!(
            expected = %payload.block().hash(),
            got = %built_payload.block().hash(),
            "flashblock hash mismatch after execution"
        );
        bail!("flashblock hash mismatch after execution");
    }

    tracing::info!(header = ?built_payload.block().header(), "successfully executed flashblock");
    Ok((built_payload, fb_payload))
}

#[allow(clippy::too_many_arguments)]
fn execute_transactions(
    info: &mut ExecutionInfo<ExtraExecutionInfo>,
    state: &mut State<impl alloy_evm::Database>,
    txs: Vec<op_alloy_consensus::OpTxEnvelope>,
    gas_limit: u64,
    evm_config: &reth_optimism_evm::OpEvmConfig,
    evm_env: alloy_evm::EvmEnv<op_revm::OpSpecId>,
    max_gas_per_txn: Option<u64>,
    is_canyon_active: bool,
    is_regolith_active: bool,
) -> eyre::Result<()> {
    use alloy_evm::{Evm as _, EvmError as _};
    use op_revm::{OpTransaction, transaction::deposit::DepositTransactionParts};
    use reth_evm::ConfigureEvm as _;
    use reth_primitives_traits::SignerRecoverable as _;
    use revm::{
        DatabaseCommit as _,
        context::{TxEnv, result::ResultAndState},
    };

    let mut evm = evm_config.evm_with_env(&mut *state, evm_env);

    for tx in txs {
        let sender = tx
            .recover_signer()
            .wrap_err("failed to recover tx signer")?;
        let tx_env = TxEnv::from_recovered_tx(&tx, sender);
        let executable_tx = match tx {
            OpTxEnvelope::Deposit(ref tx) => {
                let deposit = DepositTransactionParts {
                    mint: Some(tx.mint),
                    source_hash: tx.source_hash,
                    is_system_transaction: tx.is_system_transaction,
                };
                OpTransaction {
                    base: tx_env,
                    enveloped_tx: None,
                    deposit,
                }
            }
            OpTxEnvelope::Legacy(_) => {
                let mut tx = OpTransaction::new(tx_env);
                tx.enveloped_tx = Some(vec![0x00].into());
                tx
            }
            OpTxEnvelope::Eip2930(_) => {
                let mut tx = OpTransaction::new(tx_env);
                tx.enveloped_tx = Some(vec![0x00].into());
                tx
            }
            OpTxEnvelope::Eip1559(_) => {
                let mut tx = OpTransaction::new(tx_env);
                tx.enveloped_tx = Some(vec![0x00].into());
                tx
            }
            OpTxEnvelope::Eip7702(_) => {
                let mut tx = OpTransaction::new(tx_env);
                tx.enveloped_tx = Some(vec![0x00].into());
                tx
            }
        };

        let ResultAndState { result, state } = match evm.transact_raw(executable_tx) {
            Ok(res) => res,
            Err(err) => {
                if let Some(err) = err.as_invalid_tx_err() {
                    // TODO: what invalid txs are allowed in the block?
                    // reverting txs should be allowed (?) but not straight up invalid ones
                    tracing::error!(error = %err, "skipping invalid transaction in flashblock");
                    continue;
                }
                return Err(err).wrap_err("failed to execute flashblock transaction");
            }
        };

        if let Some(max_gas_per_txn) = max_gas_per_txn {
            if result.gas_used() > max_gas_per_txn {
                return Err(eyre::eyre!(
                    "transaction exceeded max gas per txn limit in flashblock"
                ));
            }
        }

        let tx_gas_used = result.gas_used();
        info.cumulative_gas_used = info
            .cumulative_gas_used
            .checked_add(tx_gas_used)
            .ok_or_else(|| {
                eyre::eyre!("total gas used overflowed when executing flashblock transactions")
            })?;
        if info.cumulative_gas_used > gas_limit {
            bail!("flashblock exceeded gas limit when executing transactions");
        }

        let depositor_nonce = (is_regolith_active && tx.is_deposit())
            .then(|| {
                evm.db_mut()
                    .load_cache_account(sender)
                    .map(|acc| acc.account_info().unwrap_or_default().nonce)
            })
            .transpose()
            .wrap_err("failed to get depositor nonce")?;

        let ctx = ReceiptBuilderCtx {
            tx: &tx,
            evm: &evm,
            result,
            state: &state,
            cumulative_gas_used: info.cumulative_gas_used,
        };

        info.receipts.push(build_receipt(
            evm_config,
            ctx,
            depositor_nonce,
            is_canyon_active,
        ));

        evm.db_mut().commit(state);

        // append sender and transaction to the respective lists
        info.executed_senders.push(sender);
        info.executed_transactions.push(tx.clone());
    }

    Ok(())
}

fn build_receipt<E: alloy_evm::Evm>(
    evm_config: &OpEvmConfig,
    ctx: ReceiptBuilderCtx<'_, OpTransactionSigned, E>,
    deposit_nonce: Option<u64>,
    is_canyon_active: bool,
) -> OpReceipt {
    use alloy_consensus::Eip658Value;
    use alloy_op_evm::block::receipt_builder::OpReceiptBuilder as _;
    use op_alloy_consensus::OpDepositReceipt;
    use reth_evm::ConfigureEvm as _;

    let receipt_builder = evm_config.block_executor_factory().receipt_builder();
    match receipt_builder.build_receipt(ctx) {
        Ok(receipt) => receipt,
        Err(ctx) => {
            let receipt = alloy_consensus::Receipt {
                // Success flag was added in `EIP-658: Embedding transaction status code
                // in receipts`.
                status: Eip658Value::Eip658(ctx.result.is_success()),
                cumulative_gas_used: ctx.cumulative_gas_used,
                logs: ctx.result.into_logs(),
            };

            receipt_builder.build_deposit_receipt(OpDepositReceipt {
                inner: receipt,
                deposit_nonce,
                // The deposit receipt version was introduced in Canyon to indicate an
                // update to how receipt hashes should be computed
                // when set. The state transition process ensures
                // this is only set for post-Canyon deposit
                // transactions.
                deposit_receipt_version: is_canyon_active.then_some(1),
            })
        }
    }
}

fn is_canyon_active(chain_spec: &OpChainSpec, timestamp: u64) -> bool {
    use reth_optimism_chainspec::OpHardforks as _;
    chain_spec.is_canyon_active_at_timestamp(timestamp)
}

fn is_regolith_active(chain_spec: &OpChainSpec, timestamp: u64) -> bool {
    use reth_optimism_chainspec::OpHardforks as _;
    chain_spec.is_regolith_active_at_timestamp(timestamp)
}
