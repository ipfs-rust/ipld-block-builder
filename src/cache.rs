use crate::batch::Batch;
use crate::builder::BlockBuilder;
use crate::codec::{Decoder, Encoder};
use cached::stores::SizedCache;
use cached::Cached;
use libipld::cid::Cid;
use libipld::codec::{Decode, Encode};
use libipld::error::Result;
use libipld::store::{ReadonlyStore, Store};
use std::marker::PhantomData;

/// Cache for ipld blocks.
pub struct Cache<S, C, T> {
    builder: BlockBuilder<S, C>,
    cache: SizedCache<Cid, T>,
}

impl<S: ReadonlyStore, C: Decoder, T: Clone + Decode<C::Codec>> Cache<S, C, T> {
    /// Creates a new cache of size `size`.
    pub fn new(store: S, codec: C, size: usize) -> Self {
        Self {
            builder: BlockBuilder::new(store, codec),
            cache: SizedCache::with_size(size),
        }
    }

    /// Returns a decoded block.
    pub async fn get(&mut self, cid: &Cid) -> Result<T> {
        if let Some(value) = self.cache.cache_get(cid).cloned() {
            return Ok(value);
        }
        let value: T = self.builder.get(cid).await?;
        self.cache.cache_set(cid.clone(), value.clone());
        Ok(value)
    }
}

impl<S: Store, C, T> Cache<S, C, T>
where
    C: Decoder + Encoder + Clone,
    T: Clone + Decode<<C as Decoder>::Codec> + Encode<<C as Encoder>::Codec>,
{
    /// Creates a typed batch.
    pub fn create_batch(&self) -> CacheBatch<C, T> {
        CacheBatch::new(self.builder.codec().clone())
    }

    /// Creates a typed batch.
    pub fn create_batch_with_capacity(&self, capacity: usize) -> CacheBatch<C, T> {
        CacheBatch::with_capacity(self.builder.codec().clone(), capacity)
    }

    /// Inserts a batch into the store.
    pub async fn insert_batch(&mut self, batch: CacheBatch<C, T>) -> Result<Cid> {
        let cid = self.builder.insert_batch(batch.batch).await?;
        for (cid, value) in batch.cache {
            self.cache.cache_set(cid, value);
        }
        Ok(cid)
    }

    /// Encodes and inserts a block.
    pub async fn insert(&mut self, value: T) -> Result<Cid> {
        let cid = self.builder.insert(&value).await?;
        self.cache.cache_set(cid.clone(), value);
        Ok(cid)
    }

    /// Unpins a block.
    pub async fn unpin(&mut self, cid: &Cid) -> Result<()> {
        self.builder.unpin(cid).await
    }
}

/// Typed batch.
pub struct CacheBatch<C, T> {
    _marker: PhantomData<T>,
    cache: Vec<(Cid, T)>,
    batch: Batch<C>,
}

impl<C: Encoder, T: Encode<C::Codec>> CacheBatch<C, T> {
    pub fn new(codec: C) -> Self {
        Self {
            _marker: PhantomData,
            cache: Default::default(),
            batch: Batch::new(codec),
        }
    }

    pub fn with_capacity(codec: C, capacity: usize) -> Self {
        Self {
            _marker: PhantomData,
            cache: Vec::with_capacity(capacity),
            batch: Batch::with_capacity(codec, capacity),
        }
    }

    pub fn insert(&mut self, value: T) -> Result<&Cid> {
        let cid = self.batch.insert(&value)?;
        self.cache.push((cid.clone(), value));
        Ok(cid)
    }
}
