//! Custom OpEvm implementation that allows overriding parts of execution.
//!
//! This is based on the reference `op_revm::OpEvm` but lives in this crate
//! to allow customization of the execution process.

use op_revm::precompiles::OpPrecompiles;
use revm::{
    Database, Inspector,
    context::{ContextError, ContextSetters, Evm, FrameStack},
    context_interface::ContextTr,
    handler::{
        EthFrame, EvmTr, FrameInitOrResult, ItemOrResult, PrecompileProvider,
        evm::FrameTr,
        instructions::{EthInstructions, InstructionProvider},
    },
    inspector::{InspectorEvmTr, JournalExt},
    interpreter::{InterpreterResult, interpreter::EthInterpreter},
};

/// Custom Optimism EVM that wraps the base [`Evm`] type.
///
/// This implementation mirrors `op_revm::OpEvm` but lives in this crate
/// to allow overriding parts of the execution process.
#[derive(Debug, Clone)]
pub struct OpLazyEvmInner<
    CTX,
    INSP,
    I = EthInstructions<EthInterpreter, CTX>,
    P = OpPrecompiles,
    F = EthFrame<EthInterpreter>,
>(
    /// Inner EVM type.
    pub Evm<CTX, INSP, I, P, F>,
);

impl<CTX: ContextTr, INSP>
    OpLazyEvmInner<CTX, INSP, EthInstructions<EthInterpreter, CTX>, OpPrecompiles>
{
    /// Create a new custom Optimism EVM.
    pub fn new(ctx: CTX, inspector: INSP) -> Self {
        Self(Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles: OpPrecompiles::default(),
            frame_stack: FrameStack::new_prealloc(8),
        })
    }
}

impl<CTX, INSP, I, P> OpLazyEvmInner<CTX, INSP, I, P> {
    /// Consumes self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> OpLazyEvmInner<CTX, OINSP, I, P> {
        OpLazyEvmInner(self.0.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles<OP>(self, precompiles: OP) -> OpLazyEvmInner<CTX, INSP, I, OP> {
        OpLazyEvmInner(self.0.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> INSP {
        self.0.into_inspector()
    }
}

impl<CTX, INSP, I, P> InspectorEvmTr for OpLazyEvmInner<CTX, INSP, I, P>
where
    CTX: ContextTr<Journal: JournalExt> + ContextSetters,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
    INSP: Inspector<CTX, I::InterpreterTypes>,
{
    type Inspector = INSP;

    #[inline]
    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.0.all_inspector()
    }

    #[inline]
    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        self.0.all_mut_inspector()
    }
}

impl<CTX, INSP, I, P> EvmTr for OpLazyEvmInner<CTX, INSP, I, P, EthFrame<EthInterpreter>>
where
    CTX: ContextTr,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Context = CTX;
    type Instructions = I;
    type Precompiles = P;
    type Frame = EthFrame<EthInterpreter>;

    #[inline]
    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.0.all()
    }

    #[inline]
    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.0.all_mut()
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_init(frame_input)
    }

    fn frame_run(
        &mut self,
    ) -> Result<
        FrameInitOrResult<Self::Frame>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_run()
    }

    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<
        Option<<Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_return_result(result)
    }
}
