use crate::{
    builders::flashblocks::{ctx::OpPayloadSyncerCtx, p2p::Message, payload::ExtraExecutionInfo},
    gas_limiter::{AddressGasLimiter, args::GasLimiterArgs},
    metrics::OpRBuilderMetrics,
    primitives::reth::ExecutionInfo,
    traits::ClientBounds,
};
use alloy_evm::eth::receipt_builder::ReceiptBuilderCtx;
use eyre::WrapErr as _;
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
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};
use tokio::sync::mpsc;

pub(crate) struct PayloadHandler<Client> {
    // receives new payloads built by us.
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

        tracing::info!("flashblocks payload handler started");

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
                            tracing::info!("successfully executed flashblock");
                            let _  = payload_events_handle.send(Events::BuiltPayload(payload)); // TODO is this only for built or also synced?
                        }
                        Ok(Err(e)) => {
                            tracing::error!(error = %e, "failed to execute flashblock");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "task panicked while executing flashblock");
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
    use reth_evm::{ConfigureEvm as _, execute::BlockBuilder as _};
    use reth_optimism_chainspec::OpHardforks as _;
    use reth_payload_primitives::PayloadBuilderAttributes as _;

    let mut cached_reads = reth::revm::cached::CachedReads::default(); // TODO: pass this in from somewhere
    let payload_config = PayloadConfig::new(
        Arc::new(payload.block().sealed_header().clone()),
        OpPayloadBuilderAttributes::default(),
    );

    let state_provider = client.state_by_block_hash(payload_config.parent_header.hash())?;
    let db = StateProviderDatabase::new(&state_provider);
    let mut state = State::builder()
        .with_database(cached_reads.as_db_mut(db))
        .with_bundle_update()
        .build();

    let chain_spec = client.chain_spec();
    let timestamp = payload_config.attributes.timestamp();
    let block_env_attributes = OpNextBlockEnvAttributes {
        timestamp,
        suggested_fee_recipient: payload_config.attributes.suggested_fee_recipient(),
        prev_randao: payload_config.attributes.prev_randao(),
        gas_limit: payload_config
            .attributes
            .gas_limit
            .unwrap_or(payload_config.parent_header.gas_limit),
        parent_beacon_block_root: payload_config
            .attributes
            .payload_attributes
            .parent_beacon_block_root,
        extra_data: if chain_spec.is_holocene_active_at_timestamp(timestamp) {
            payload_config
                .attributes
                .get_holocene_extra_data(chain_spec.base_fee_params_at_timestamp(timestamp))
                .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
        } else {
            Default::default()
        },
    };

    let evm_env = ctx
        .evm_config()
        .next_evm_env(&payload_config.parent_header, &block_env_attributes)
        .wrap_err("failed to create next evm env")?;

    let address_gas_limiter = AddressGasLimiter::new(gas_limiter_config);
    // TODO: can probably refactor this
    let builder_ctx = ctx.into_op_payload_builder_ctx(
        payload_config,
        evm_env.clone(),
        block_env_attributes,
        cancel,
        metrics,
        address_gas_limiter,
    );

    // copy of `execute_pre_steps()`
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
    let mut info: ExecutionInfo<ExtraExecutionInfo> = builder_ctx
        .execute_sequencer_transactions(&mut state)
        .wrap_err("failed to execute sequencer transactions")?;

    execute_transactions(
        &mut info,
        &mut state,
        &mut FlashblockTransactions::new(payload.block().body().transactions.clone()), // TODO: unnecessary
        payload.block().header().gas_used,
        &builder_ctx.evm_config,
        evm_env,
        builder_ctx.max_gas_per_txn,
        is_canyon_active(&chain_spec, timestamp),
    )
    .wrap_err("failed to execute best transactions")?;

    let (payload, fb_payload) = crate::builders::flashblocks::payload::build_block(
        &mut state,
        &builder_ctx,
        &mut info,
        true, // TODO: do we need this always?
    )?;

    Ok((payload, fb_payload))
}

struct FlashblockTransactions {
    txs: VecDeque<OpTransactionSigned>,
    invalid_txs: HashSet<alloy_primitives::B256>,
}

impl FlashblockTransactions {
    fn new(txs: Vec<OpTransactionSigned>) -> Self {
        Self {
            txs: txs.into(),
            invalid_txs: HashSet::new(),
        }
    }
}

impl reth_payload_util::PayloadTransactions for FlashblockTransactions {
    type Transaction = OpTransactionSigned;

    /// Exclude descendants of the transaction with given sender and nonce from the iterator,
    /// because this transaction won't be included in the block.
    fn mark_invalid(&mut self, sender: alloy_primitives::Address, nonce: u64) {
        use alloy_consensus::Transaction as _;
        use reth_primitives_traits::SignerRecoverable as _;

        for tx in &self.txs {
            let Ok(signer) = tx.recover_signer() else {
                self.invalid_txs.insert(*tx.hash());
                continue;
            };

            if signer == sender && tx.nonce() >= nonce {
                self.invalid_txs.insert(*tx.hash());
            }
        }
    }

    fn next(&mut self, _ctx: ()) -> Option<Self::Transaction> {
        while let Some(tx) = self.txs.pop_front() {
            if !self.invalid_txs.contains(tx.hash()) {
                return Some(tx);
            }
        }
        None
    }
}

fn execute_transactions(
    info: &mut ExecutionInfo<ExtraExecutionInfo>,
    state: &mut State<impl alloy_evm::Database>,
    txs: &mut impl reth_payload_util::PayloadTransactions<Transaction = OpTransactionSigned>,
    gas_limit: u64,
    evm_config: &reth_optimism_evm::OpEvmConfig,
    evm_env: alloy_evm::EvmEnv<op_revm::OpSpecId>,
    max_gas_per_txn: Option<u64>,
    is_canyon_active: bool,
) -> eyre::Result<()> {
    use alloy_evm::{Evm as _, EvmError as _};
    use op_revm::{OpTransaction, transaction::deposit::DepositTransactionParts};
    use reth_evm::ConfigureEvm as _;
    use reth_primitives_traits::SignerRecoverable as _;
    use revm::{
        DatabaseCommit as _,
        context::{TxEnv, result::ResultAndState},
    };

    let mut gas_used: u64 = 0;
    let mut evm = evm_config.evm_with_env(&mut *state, evm_env);

    while let Some(ref tx) = txs.next(()) {
        let sender = tx
            .recover_signer()
            .wrap_err("failed to recover tx signer")?;
        let tx_env = TxEnv::from_recovered_tx(&tx, sender);
        let executable_tx = match tx {
            OpTxEnvelope::Deposit(tx) => {
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
            OpTxEnvelope::Legacy(_) => OpTransaction::new(tx_env),
            OpTxEnvelope::Eip2930(_) => OpTransaction::new(tx_env),
            OpTxEnvelope::Eip1559(_) => OpTransaction::new(tx_env),
            OpTxEnvelope::Eip7702(_) => OpTransaction::new(tx_env),
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
        gas_used = gas_used.checked_add(tx_gas_used).ok_or_else(|| {
            eyre::eyre!("total gas used overflowed when executing flashblock transactions")
        })?;
        if gas_used > gas_limit {
            return Err(eyre::eyre!(
                "flashblock exceeded gas limit when executing transactions"
            ));
        }

        info.cumulative_gas_used += gas_used;
        // info.cumulative_da_bytes_used += tx_da_size;

        let ctx = ReceiptBuilderCtx {
            tx,
            evm: &evm,
            result,
            state: &state,
            cumulative_gas_used: info.cumulative_gas_used,
        };
        // TODO: deposit_nonce may be Some in the case of a sequencer tx
        info.receipts
            .push(build_receipt(evm_config, ctx, None, is_canyon_active));

        evm.db_mut().commit(state);

        // // update add to total fees
        // let miner_fee = tx
        //     .effective_tip_per_gas(base_fee)
        //     .expect("fee is always valid; execution succeeded");
        // info.total_fees += U256::from(miner_fee) * U256::from(gas_used);

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
