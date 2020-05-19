use crate::block::decode;
use crate::cid::Cid;
use crate::codec::{Codec, Decode};
use crate::error::Result;
use crate::store::ReadonlyStore;
use cached::Cached;
use cached::stores::SizedCache;
use core::marker::PhantomData;

/// Cache for ipld blocks.
pub struct GenericCache<'a, S, C, T> {
    _marker: PhantomData<C>,
    cache: SizedCache<Cid, T>,
    store: &'a S,
}

impl<'a, S: ReadonlyStore, C: Codec, T: Clone + Decode<C>> GenericCache<'a, S, C, T> {
    /// Creates a new cache of size `size`.
    pub fn with_size(store: &'a S, size: usize) -> Self {
        Self {
            _marker: PhantomData,
            cache: SizedCache::with_size(size),
            store,
        }
    }

    /// Returns a decoded block.
    pub async fn get(&mut self, cid: &Cid) -> Result<T> {
        if let Some(value) = self.cache.cache_get(cid).cloned() {
            return Ok(value);
        }
        let data = self.store.get(cid).await?;
        let value = decode::<C, T>(cid, &data)?;
        self.cache.cache_set(cid.clone(), value.clone());
        Ok(value)
    }
}
