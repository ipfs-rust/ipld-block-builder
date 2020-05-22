use crate::codec::Encoder;
use libipld::block::Block;
use libipld::cid::Cid;
use libipld::codec::Encode;
use libipld::error::Result;

/// Batch of blocks to insert atomically.
pub struct Batch<C> {
    codec: C,
    blocks: Vec<Block>,
}

impl<C> Batch<C>{
    /// Creates a new batch.
    pub fn new(codec: C) -> Self {
        Self {
            codec,
            blocks: Default::default(),
        }
    }

    /// Creates a new batch with capacity.
    pub fn with_capacity(codec: C, capacity: usize) -> Self {
        Self {
            codec,
            blocks: Vec::with_capacity(capacity),
        }
    }

    /// Returns an iterator of `Block`.
    pub fn into_vec(self) -> Vec<Block> {
        self.blocks
    }
}

impl<C: Encoder> Batch<C> {
    /// Inserts a block into the batch.
    pub fn insert<T: Encode<C::Codec>>(&mut self, value: &T) -> Result<&Cid> {
        let block = self.codec.encode(value)?;
        self.blocks.push(block);
        Ok(&self.blocks.last().unwrap().cid)
    }
}
