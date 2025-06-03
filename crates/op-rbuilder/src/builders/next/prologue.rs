//! This module implements the default prologue logic for blocks built with op-rbuilder.
//!
//! By default, it will insert a builder transaction at the end of the block signed by
//! the builder's secret key.

use super::payload::PayloadBuilderContext;
use crate::traits::ClientBounds;

pub fn default_block_prologue<Client: ClientBounds>(_builder: &mut PayloadBuilderContext<Client>) {}
