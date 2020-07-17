use crate::batch::Batch;
use crate::builder::BlockBuilder;
use crate::codec::{Decoder, Encoder};
use async_std::sync::Mutex;
use async_trait::async_trait;
use cached::stores::SizedCache;
use cached::Cached;
use libipld::cid::Cid;
use libipld::codec::{Decode, Encode};
use libipld::error::Result;
use libipld::store::{ReadonlyStore, Store};
use std::marker::PhantomData;

/// Cache for ipld blocks.
pub struct IpldCache<S, C, T> {
    builder: BlockBuilder<S, C>,
    cache: Mutex<SizedCache<Cid, T>>,
}

impl<S, C, T> IpldCache<S, C, T> {
    /// Creates a new cache of size `size`.
    pub fn new(store: S, codec: C, size: usize) -> Self {
        Self {
            builder: BlockBuilder::new(store, codec),
            cache: Mutex::new(SizedCache::with_size(size)),
        }
    }
}

/// Readonly cache trait.
#[async_trait]
pub trait ReadonlyCache<C, T>
where
    C: Decoder + Clone + Send + Sync,
    T: Decode<<C as Decoder>::Codec> + Clone + Send + Sync,
{
    /// Returns a decoded block.
    async fn get(&self, cid: &Cid) -> Result<T>;
}

#[async_trait]
impl<S: ReadonlyStore + Send + Sync, C, T> ReadonlyCache<C, T> for IpldCache<S, C, T>
where
    C: Decoder + Clone + Send + Sync,
    T: Decode<<C as Decoder>::Codec> + Clone + Send + Sync,
{
    async fn get(&self, cid: &Cid) -> Result<T> {
        if let Some(value) = self.cache.lock().await.cache_get(cid).cloned() {
            return Ok(value);
        }
        let value: T = self.builder.get(cid).await?;
        self.cache
            .lock()
            .await
            .cache_set(cid.clone(), value.clone());
        Ok(value)
    }
}

/// Cache trait.
#[async_trait]
pub trait Cache<C, T>: ReadonlyCache<C, T>
where
    C: Decoder + Encoder + Clone + Send + Sync,
    T: Decode<<C as Decoder>::Codec> + Encode<<C as Encoder>::Codec> + Clone + Send + Sync,
{
    /// Creates a typed batch.
    fn create_batch(&self) -> CacheBatch<C, T>;

    /// Creates a typed batch.
    fn create_batch_with_capacity(&self, capacity: usize) -> CacheBatch<C, T>;

    /// Inserts a batch into the store.
    async fn insert_batch(&self, batch: CacheBatch<C, T>) -> Result<Cid>;

    /// Encodes and inserts a block.
    async fn insert(&self, value: T) -> Result<Cid>;

    /// Flushes all buffers.
    async fn flush(&self) -> Result<()>;

    /// Unpins a block.
    async fn unpin(&self, cid: &Cid) -> Result<()>;
}

#[async_trait]
impl<S: Store + Send + Sync, C, T> Cache<C, T> for IpldCache<S, C, T>
where
    C: Decoder + Encoder + Clone + Send + Sync,
    T: Decode<<C as Decoder>::Codec> + Encode<<C as Encoder>::Codec> + Clone + Send + Sync,
{
    fn create_batch(&self) -> CacheBatch<C, T> {
        CacheBatch::new(self.builder.codec().clone())
    }

    fn create_batch_with_capacity(&self, capacity: usize) -> CacheBatch<C, T> {
        CacheBatch::with_capacity(self.builder.codec().clone(), capacity)
    }

    async fn insert_batch(&self, batch: CacheBatch<C, T>) -> Result<Cid> {
        let cid = self.builder.insert_batch(batch.batch).await?;
        let mut cache = self.cache.lock().await;
        for (cid, value) in batch.cache {
            cache.cache_set(cid, value);
        }
        Ok(cid)
    }

    async fn insert(&self, value: T) -> Result<Cid> {
        let cid = self.builder.insert(&value).await?;
        self.cache.lock().await.cache_set(cid.clone(), value);
        Ok(cid)
    }

    async fn flush(&self) -> Result<()> {
        self.builder.flush().await
    }

    async fn unpin(&self, cid: &Cid) -> Result<()> {
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
    /// Creates a new batch.
    pub fn new(codec: C) -> Self {
        Self {
            _marker: PhantomData,
            cache: Default::default(),
            batch: Batch::new(codec),
        }
    }

    /// Creates a new batch with capacity.
    pub fn with_capacity(codec: C, capacity: usize) -> Self {
        Self {
            _marker: PhantomData,
            cache: Vec::with_capacity(capacity),
            batch: Batch::with_capacity(codec, capacity),
        }
    }

    /// Inserts a value into the batch.
    pub fn insert(&mut self, value: T) -> Result<&Cid> {
        let cid = self.batch.insert(&value)?;
        self.cache.push((cid.clone(), value));
        Ok(cid)
    }
}

/// Macro to derive cache trait for a struct.
#[macro_export]
macro_rules! derive_cache {
    ($struct:tt, $field:ident, $codec:ty, $type:ty) => {
        #[async_trait::async_trait]
        impl<S> $crate::ReadonlyCache<$codec, $type> for $struct<S>
        where
            S: libipld::store::ReadonlyStore + Send + Sync,
        {
            async fn get(&self, cid: &libipld::cid::Cid) -> libipld::error::Result<$type> {
                self.$field.get(cid).await
            }
        }

        #[async_trait::async_trait]
        impl<S> $crate::Cache<$codec, $type> for $struct<S>
        where
            S: libipld::store::Store + Send + Sync,
        {
            fn create_batch(&self) -> $crate::CacheBatch<$codec, $type> {
                self.$field.create_batch()
            }

            fn create_batch_with_capacity(
                &self,
                capacity: usize,
            ) -> $crate::CacheBatch<$codec, $type> {
                self.$field.create_batch_with_capacity(capacity)
            }

            async fn insert_batch(
                &self,
                batch: $crate::CacheBatch<$codec, $type>,
            ) -> libipld::error::Result<libipld::cid::Cid> {
                self.$field.insert_batch(batch).await
            }

            async fn insert(&self, value: $type) -> libipld::error::Result<libipld::cid::Cid> {
                self.$field.insert(value).await
            }

            async fn flush(&self) -> libipld::error::Result<()> {
                self.$field.flush().await
            }

            async fn unpin(&self, cid: &libipld::cid::Cid) -> libipld::error::Result<()> {
                self.$field.unpin(cid).await
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Codec;
    use libipld::mem::MemStore;

    struct OffchainClient<S> {
        number: IpldCache<S, Codec, u32>,
    }

    derive_cache!(OffchainClient, number, Codec, u32);

    #[async_std::test]
    async fn test_cache() {
        let store = MemStore::default();
        let codec = Codec::new();
        let client = OffchainClient {
            number: IpldCache::new(store, codec, 1),
        };
        let cid = client.insert(42).await.unwrap();
        let res = client.get(&cid).await.unwrap();
        assert_eq!(res, 42);
    }
}
