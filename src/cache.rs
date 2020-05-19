use crate::batch::Batch;
use crate::codec::{Decoder, Encoder};
use cached::Cached;
use cached::stores::SizedCache;
use libipld::cid::Cid;
use libipld::codec::{Decode, Encode};
use libipld::error::Result;
use libipld::store::{ReadonlyStore, Store};
use smallvec::SmallVec;
use std::marker::PhantomData;

/// Cache for ipld blocks.
pub struct Cache<'a, S, C, T> {
    store: &'a S,
    codec: &'a C,
    cache: SizedCache<Cid, T>,
}

impl<'a, S: ReadonlyStore, C: Decoder, T: Clone + Decode<C::Codec>> Cache<'a, S, C, T> {
    /// Creates a new cache of size `size`.
    pub fn new(store: &'a S, codec: &'a C, size: usize) -> Self {
        Self {
            store,
            codec,
            cache: SizedCache::with_size(size),
        }
    }

    /// Returns a decoded block.
    pub async fn get(&mut self, cid: &Cid) -> Result<T> {
        if let Some(value) = self.cache.cache_get(cid).cloned() {
            return Ok(value);
        }
        let data = self.store.get(cid).await?;
        let value: T = self.codec.decode(cid, &data)?;
        self.cache.cache_set(cid.clone(), value.clone());
        Ok(value)
    }
}

impl<'a, S: Store, C, T> Cache<'a, S, C, T>
where
    C: Decoder + Encoder,
    T: Clone + Decode<<C as Decoder>::Codec> + Encode<<C as Encoder>::Codec>,
{
    /// Creates a typed batch.
    pub fn create_batch(&self) -> CacheBatch<'a, C, T> {
        CacheBatch::new(&self.codec)
    }

    /// Inserts a batch into the store.
    pub async fn insert_batch(&mut self, batch: CacheBatch<'_, C, T>) -> Result<Cid> {
        println!("doesn't do anything to the store yet");
        //let cid = self.store.insert_batch(batch.batch).await?;
        let cid = batch.cache.last().map(|(cid, _)| cid).cloned().unwrap();
        for (cid, value) in batch.cache {
            self.cache.cache_set(cid, value);
        }
        Ok(cid)
    }
}

/// Typed batch.
pub struct CacheBatch<'a, C, T> {
    _marker: PhantomData<T>,
    cache: SmallVec<[(Cid, T); 8]>,
    batch: Batch<'a, C>,
}

impl<'a, C: Encoder, T: Encode<C::Codec>> CacheBatch<'a, C, T> {
    pub fn new(codec: &'a C) -> Self {
        Self {
            _marker: PhantomData,
            cache: Default::default(),
            batch: Batch::new(codec),
        }
    }

    pub fn insert(&mut self, value: T) -> Result<&Cid> {
        let cid = self.batch.insert(&value)?;
        self.cache.push((cid.clone(), value));
        Ok(cid)
    }
}
