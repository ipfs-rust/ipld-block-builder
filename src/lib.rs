//! Block builder.
#![deny(missing_docs)]
#![deny(warnings)]

mod batch;
mod builder;
mod cache;
#[cfg(feature = "crypto")]
mod crypto;
mod path;

pub use batch::GenericBatch;
pub use builder::GenericBlockBuilder;
pub use cache::GenericCache;
#[cfg(feature = "crypto")]
pub use crypto::{Error, Key};
pub use libipld::*;
pub use path::DagPath;

use crate::cbor::DagCbor;
use crate::multihash::Blake2b256;

/// Default batch.
pub type Batch<'a> = GenericBatch<'a, DagCbor, Blake2b256>;
/// Default block builder.
pub type BlockBuilder<S> = GenericBlockBuilder<S, Blake2b256, DagCbor>;
