
pub use alloy_evm::op::{spec, spec_by_timestamp_after_bedrock};

use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, Bytes};
use reth_evm::precompiles::PrecompilesMap;
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use op_revm::{
    DefaultOp, L1BlockInfo, OpBuilder, OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError, api::OpContextTr, precompiles::OpPrecompiles, transaction::OpTxTr
};
use revm::{
    Context, ExecuteEvm, InspectEvm, InspectSystemCallEvm, Inspector, SystemCallEvm, context::{BlockEnv, Cfg, ContextError, FrameStack, TxEnv}, context_interface::result::{EVMError, ResultAndState}, handler::{EthFrame, FrameInitOrResult, FrameTr, ItemOrResult, PrecompileProvider, SystemCallTx, instructions::{EthInstructions, InstructionProvider}}, inspector::{InspectorEvmTr, NoOpInspector}, interpreter::{InterpreterResult, interpreter::EthInterpreter}, primitives::HashMap, state::EvmState
};
use revm::{
    context::{
        result::{ExecResultAndState},
        ContextSetters,
    },
    context_interface::{
        result::{ExecutionResult},
        ContextTr, JournalTr,
    },
    handler::{EvmTr, Handler},
    inspector::{InspectCommitEvm, InspectorHandler, JournalExt},
    DatabaseCommit, ExecuteCommitEvm,
};

use crate::block_stm::evm::handler::LazyRevmHandler;

mod handler;


/// OP EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`OpEvm`](op_revm::OpEvm) type.
#[allow(missing_debug_implementations)] // missing revm::OpContext Debug impl
pub struct OpLazyEvm<DB: Database, I, P> {
    inner: op_revm::OpEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
    inspect: bool,
}


impl<DB: Database, I, P> OpLazyEvm<DB, I, P> {
    /// Creates a new OP EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] of the given
    /// [`OpEvm`](op_revm::OpEvm) should be invoked on [`Evm::transact`].
    pub const fn new(
        evm: op_revm::OpEvm<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
        inspect: bool,
    ) -> Self {
        Self { inner: evm, inspect }
    }

    pub fn to_inner(self) -> OpEvm<DB, I, P> {
        OpEvm::new(self.inner, self.inspect)
    }
}

impl<DB: Database, I, P> Deref for OpLazyEvm<DB, I, P> {
    type Target = OpContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner.0.ctx
    }
}

impl<DB: Database, I, P> DerefMut for OpLazyEvm<DB, I, P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.0.ctx
    }
}

impl<DB, I, P> Evm for OpLazyEvm<DB, I, P>
where
    DB: Database,
    I: Inspector<OpContext<DB>>,
    P: PrecompileProvider<OpContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = OpTransaction<TxEnv>;
    type Error = EVMError<DB::Error, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = P;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context { block: block_env, cfg: cfg_env, journaled_state, .. } = self.inner.0.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.0.ctx.journaled_state.database,
            &self.inner.0.inspector,
            &self.inner.0.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.0.ctx.journaled_state.database,
            &mut self.inner.0.inspector,
            &mut self.inner.0.precompiles,
        )
    }
}

/// Factory producing [`OpLazyEvm`]s.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct OpLazyEvmFactory;

impl EvmFactory for OpLazyEvmFactory {
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = OpLazyEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = OpTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let spec_id = input.cfg_env.spec;
        OpLazyEvm::new(Context::op()
        .with_db(db)
        .with_block(input.block_env)
        .with_cfg(input.cfg_env)
        .build_op_with_inspector(NoOpInspector {})
        .with_precompiles(
            PrecompilesMap::from_static(OpPrecompiles::new_with_spec(spec_id).precompiles()),
        )
                    , false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec_id = input.cfg_env.spec;
        OpLazyEvm::new(
            Context::op()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_op_with_inspector(inspector)
                .with_precompiles(
                    PrecompilesMap::from_static(OpPrecompiles::new_with_spec(spec_id).precompiles()),
                ), true)
    }
}
