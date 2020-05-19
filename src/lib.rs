//! Block builder.
#![deny(missing_docs)]
#![deny(warnings)]

mod batch;
mod builder;
mod cache;
mod codec;
#[cfg(feature = "crypto")]
mod crypto;
mod path;

pub use batch::Batch;
pub use builder::BlockBuilder;
pub use cache::Cache;
pub use codec::*;
#[cfg(feature = "crypto")]
pub use crypto::{Error, Key};
pub use path::DagPath;

use libipld::cbor::DagCbor;
use libipld::multihash::Blake2b256;

/// Default codec.
pub type Codec = GenericCodec<DagCbor, Blake2b256>;
/// Default encrypted codec.
#[cfg(feature = "crypto")]
pub type StrobeCodec = GenericStrobeCodec<DagCbor, Blake2b256>;
