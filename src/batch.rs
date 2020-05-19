use crate::codec::Encoder;
use libipld::block::Block;
use libipld::cid::Cid;
use libipld::codec::Encode;
use libipld::error::Result;
use smallvec::SmallVec;

/// Batch of blocks to insert atomically.
pub struct Batch<'a, C> {
    codec: &'a C,
    blocks: SmallVec<[Block; 8]>,
}

impl<'a, C> Batch<'a, C>{
    /// Creates a new batch.
    pub fn new(codec: &'a C) -> Self {
        Self {
            codec,
            blocks: Default::default(),
        }
    }

    /// Returns an iterator of `Block`.
    pub fn into_iter(self) -> impl Iterator<Item = Block> {
        self.blocks.into_iter()
    }
}

impl<'a, C: Encoder> Batch<'a, C> {
    /// Inserts a block into the batch.
    pub fn insert<T: Encode<C::Codec>>(&mut self, value: &T) -> Result<&Cid> {
        let block = self.codec.encode(value)?;
        self.blocks.push(block);
        Ok(&self.blocks.last().unwrap().cid)
    }
}
