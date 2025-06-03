use super::{
    block::{BlockContext, PayloadAttributes},
    service::ServiceContext,
};
use crate::traits::ClientBounds;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use reth_node_api::{PayloadBuilderError, PayloadKind};
use reth_optimism_node::OpBuiltPayload;
use reth_payload_builder::{KeepPayloadJobAlive, PayloadJob as RethPayloadJobTrait};
use std::sync::Arc;
use tracing::info;

pub struct PayloadJob<Client>
where
    Client: ClientBounds,
{
    block_ctx: Arc<BlockContext<Client>>,
}

impl<Client> PayloadJob<Client>
where
    Client: ClientBounds,
{
    pub fn new(
        attribs: PayloadAttributes,
        svc: Arc<ServiceContext<Client>>,
    ) -> Result<Self, PayloadBuilderError> {
        Ok(Self {
            block_ctx: Arc::new(BlockContext::new(svc, attribs)?),
        })
    }
}

impl<Client> RethPayloadJobTrait for PayloadJob<Client>
where
    Client: ClientBounds,
{
    type PayloadAttributes = PayloadAttributes;
    type ResolvePayloadFuture = PayloadJobResolveFuture;
    type BuiltPayload = OpBuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        todo!("PayloadJob::best_payload");
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        info!("PayloadJob::payload_attributes");
        Ok(self.block_ctx.fcu_attributes().clone())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        info!("PayloadJob::resolve_kind {kind:?}");

        match kind {
            // If we need a payload asap then just create a new payload without adding
            // any transactions to it. That will return a minimal empty valid payload.
            PayloadKind::Earliest => (
                PayloadJobResolveFuture::Ready(Some(
                    self.block_ctx
                        .create_payload_builder()
                        .and_then(|builder| builder.try_into()),
                )),
                KeepPayloadJobAlive::Yes,
            ),
            PayloadKind::WaitForPending => {
                todo!("PayloadJob::resolve_kind WaitForPending");
            }
        }
    }
}

pub enum PayloadJobResolveFuture {
    Ready(Option<Result<OpBuiltPayload, PayloadBuilderError>>),
}

impl<C: ClientBounds> Future for PayloadJob<C> {
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        info!("PayloadJob::poll");
        Poll::Pending
    }
}

impl Future for PayloadJobResolveFuture {
    type Output = Result<OpBuiltPayload, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        info!("PayloadJobResolveFuture::poll");
        match self.get_mut() {
            PayloadJobResolveFuture::Ready(payload) => {
                if let Some(payload) = payload.take() {
                    Poll::Ready(payload) // return the payload only once
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
