use crate::block::{Block, encode};
use crate::cid::Cid;
use crate::codec::{Codec, Encode};
use crate::error::Result;
use crate::multihash::{Code, Multihasher};
use core::marker::PhantomData;
use smallvec::SmallVec;

/// Batch of blocks to insert atomically.
#[derive(Default)]
pub struct GenericBatch<'a, C, H> {
    _marker: PhantomData<&'a (C, H)>,
    blocks: SmallVec<[Block; 8]>,
    #[cfg(feature = "crypto")]
    key: Option<&'a Key>,
}

impl<'a, C, H> GenericBatch<'a, C, H>{
    /// Creates a new batch.
    #[cfg(not(feature = "crypto"))]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            blocks: Default::default(),
        }
    }

    /// Creates a new batch.
    #[cfg(feature = "crypto")]
    pub fn new(key: Option<&'a Key>) -> Self {
        Self {
            _marker: PhantomData,
            blocks: Default::default(),
            key,
        }
    }

    /// Returns an iterator of `Block`.
    pub fn into_iter(self) -> impl Iterator<Item = Block> {
        self.blocks.into_iter()
    }
}

impl<'a, C: Codec, H: Multihasher<Code>> GenericBatch<'a, C, H> {
    /// Inserts a block into the batch.
    pub fn insert<E: Encode<C>>(&mut self, e: &E) -> Result<&Cid> {
        #[cfg(feature = "crypto")]
        let block = if let Some(key) = self.key.as_ref() {
            let data = C::encode(e).map_err(|e| Error::CodecError(Box::new(e)))?;
            let ct =
                crypto::encrypt(key, C::CODE, &data).map_err(|e| Error::CodecError(Box::new(e)))?;
            encode::<Raw, H, _>(&ct)?
        } else {
            encode::<C, H, E>(e)?
        };
        #[cfg(not(feature = "crypto"))]
        let block = encode::<C, H, E>(e)?;
        self.blocks.push(block);
        Ok(&self.blocks.last().unwrap().cid)
    }
}
