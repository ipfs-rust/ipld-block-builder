use crate::codec::Decoder;
use cached::Cached;
use cached::stores::SizedCache;
use libipld::cid::Cid;
use libipld::codec::Decode;
use libipld::error::Result;
use libipld::store::ReadonlyStore;

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
