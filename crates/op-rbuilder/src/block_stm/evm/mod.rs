pub use alloy_evm::op::{spec, spec_by_timestamp_after_bedrock};

use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, Bytes, U256};
use core::ops::{Deref, DerefMut};
use op_revm::{
    DefaultOp, OpBuilder, OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError,
    precompiles::OpPrecompiles,
};
use reth_evm::precompiles::PrecompilesMap;
use revm::{
    Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
    context::{BlockEnv, TxEnv},
    context_interface::result::{EVMError, ResultAndState},
    handler::{PrecompileProvider, instructions::EthInstructions},
    inspector::NoOpInspector,
    interpreter::{InterpreterResult, interpreter::EthInterpreter},
};

mod custom_evm;
mod exec;
mod handler;

pub use custom_evm::OpLazyEvmInner;


/// OP EVM implementation.
///
/// This is a wrapper type around the custom [`OpLazyEvmInner`] with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime.
///
/// This uses our custom EVM implementation that allows overriding parts of the execution process.
#[allow(missing_debug_implementations)] // missing revm::OpContext Debug impl
pub struct OpLazyEvm<DB: Database, I, P> {
    inner: OpLazyEvmInner<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
    inspect: bool,
}


impl<DB: Database, I, P> OpLazyEvm<DB, I, P> {
    /// Creates a new OP EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] should be
    /// invoked on [`Evm::transact`].
    pub const fn new(
        evm: OpLazyEvmInner<OpContext<DB>, I, EthInstructions<EthInterpreter, OpContext<DB>>, P>,
        inspect: bool,
    ) -> Self {
        Self { inner: evm, inspect }
    }

    /// Converts to an `alloy_op_evm::OpEvm` by wrapping the inner EVM.
    ///
    /// Note: This creates a new `op_revm::OpEvm` from our custom inner EVM's context.
    pub fn to_inner(self) -> OpEvm<DB, I, P> {
        OpEvm::new(
            op_revm::OpEvm(self.inner.0),
            self.inspect,
        )
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
    DB: Database + LazyDatabase,
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

trait LazyDatabase {
    fn lazily_increment_balance(&self, address: Address, amount: U256);
}

/// Factory producing [`OpLazyEvm`]s.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct OpLazyEvmFactory;

impl OpLazyEvmFactory {
    pub fn create_evm<DB: Database + LazyDatabase>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
    ) -> OpLazyEvm<DB, NoOpInspector, PrecompilesMap> {
        let spec_id = input.cfg_env.spec;
        // Build the base EVM using the op_revm builder, then wrap in our custom type
        let base_evm = Context::op()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .build_op_with_inspector(NoOpInspector {})
            .with_precompiles(
                PrecompilesMap::from_static(OpPrecompiles::new_with_spec(spec_id).precompiles()),
            );
        // Convert op_revm::OpEvm to our custom OpLazyEvmInner
        OpLazyEvm::new(OpLazyEvmInner(base_evm.0), false)
    }

    pub fn create_evm_with_inspector<DB: Database + LazyDatabase, I: Inspector<OpContext<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> OpLazyEvm<DB, I, PrecompilesMap> {
        let spec_id = input.cfg_env.spec;
        // Build the base EVM using the op_revm builder, then wrap in our custom type
        let base_evm = Context::op()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .build_op_with_inspector(inspector)
            .with_precompiles(
                PrecompilesMap::from_static(OpPrecompiles::new_with_spec(spec_id).precompiles()),
            );
        // Convert op_revm::OpEvm to our custom OpLazyEvmInner
        OpLazyEvm::new(OpLazyEvmInner(base_evm.0), true)
    }
}
