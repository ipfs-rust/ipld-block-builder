use crate::batch::GenericBatch;
use crate::block::*;
use crate::cache::GenericCache;
use crate::cid::Cid;
use crate::codec::{Codec, Decode, Encode};
#[cfg(feature = "crypto")]
use crate::crypto::Key;
use crate::error::{Error, Result};
use crate::ipld::Ipld;
use crate::multihash::{Code, Multihasher};
use crate::path::DagPath;
#[cfg(feature = "crypto")]
use crate::raw::Raw;
use crate::store::{AliasStore, MultiUserStore, ReadonlyStore, Store, Visibility};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::path::Path;

/// Generic block builder for creating blocks.
pub struct GenericBlockBuilder<S, H, C> {
    _marker: PhantomData<(H, C)>,
    store: S,
    visibility: Visibility,
    #[cfg(feature = "crypto")]
    key: Option<Key>,
}

impl<S, H, C> GenericBlockBuilder<S, H, C> {
    /// Creates a builder for public blocks.
    pub fn new(store: S) -> Self {
        Self {
            _marker: PhantomData,
            store,
            visibility: Visibility::Public,
            #[cfg(feature = "crypto")]
            key: None,
        }
    }

    /// Creates a builder for private blocks.
    #[cfg(feature = "crypto")]
    pub fn new_private(store: S, key: Key) -> Self {
        Self {
            _marker: PhantomData,
            store,
            visibility: Visibility::Private,
            key: Some(key),
        }
    }
}

impl<S, H, C> Deref for GenericBlockBuilder<S, H, C> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl<S, H, C> DerefMut for GenericBlockBuilder<S, H, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

impl<S: ReadonlyStore, H, C: Codec> GenericBlockBuilder<S, H, C> {
    /// Returns the decoded block with cid.
    pub async fn get<D: Decode<C>>(&self, cid: &Cid) -> Result<D> {
        let data = self.store.get(cid).await?;
        #[cfg(feature = "crypto")]
        if let Some(key) = self.key.as_ref() {
            let ct = decode::<Raw, Box<[u8]>>(cid, &data)?;
            let (codec, data) =
                crypto::decrypt(key, ct).map_err(|e| Error::CodecError(Box::new(e)))?;
            return Ok(raw_decode::<C, D>(codec, &data)?);
        }
        Ok(decode::<C, D>(cid, &data)?)
    }

    /// Creates a new typed cache.
    pub fn create_cache<D: Clone + Decode<C>>(&self, size: usize) -> GenericCache<'_, S, C, D> {
        GenericCache::with_size(&self.store, size)
    }
}

impl<S: ReadonlyStore, H, C> GenericBlockBuilder<S, H, C> {
    /// Returns the ipld representation of a block with cid.
    pub async fn get_ipld(&self, cid: &Cid) -> Result<Ipld> {
        let data = self.store.get(cid).await?;
        #[cfg(feature = "crypto")]
        if let Some(key) = self.key.as_ref() {
            let ct = decode::<Raw, Box<[u8]>>(cid, &data)?;
            let (codec, data) =
                crypto::decrypt(key, ct).map_err(|e| Error::CodecError(Box::new(e)))?;
            return Ok(raw_decode_ipld(codec, &data)?);
        }
        Ok(decode_ipld(cid, &data)?)
    }

    /// Resolves a path recursively and returns the ipld.
    pub async fn get_path(&self, path: &DagPath<'_>) -> Result<Ipld> {
        let mut root = self.get_ipld(path.root()).await?;
        let mut ipld = &root;
        for segment in path.path().iter() {
            ipld = ipld.get(segment)?;
            if let Ipld::Link(cid) = ipld {
                root = self.get_ipld(cid).await?;
                ipld = &root;
            }
        }
        Ok(ipld.clone())
    }
}

impl<S: Store, H: Multihasher<Code>, C: Codec> GenericBlockBuilder<S, H, C> {
    /// Creates a new batch.
    pub fn create_batch<'a>(&'a self) -> GenericBatch<'a, C, H> {
        #[cfg(feature = "crypto")]
        return GenericBatch::new(&self.key);
        #[cfg(not(feature = "crypto"))]
        GenericBatch::new()
    }

    /// Encodes and inserts a block into the store.
    pub async fn insert<E: Encode<C>>(&self, e: &E) -> Result<Cid> {
        let mut batch = self.create_batch();
        batch.insert(e)?;
        self.insert_batch(batch).await
    }

    /// Inserts a batch of blocks atomically pinning the last one.
    pub async fn insert_batch<A, B>(&self, batch: GenericBatch<'_, A, B>) -> Result<Cid> {
        // TODO add insert batch to store trait
        let mut last_cid = None;
        for Block { cid, data } in batch.into_iter() {
            self.store.insert(&cid, data, self.visibility).await?;
            if let Some(cid) = last_cid.as_ref() {
                self.unpin(cid).await?;
            }
            last_cid = Some(cid);
        }
        // TODO add EmptyBatch error
        last_cid.ok_or(Error::BlockTooLarge(0))
    }
}

impl<S: Store, H, C> GenericBlockBuilder<S, H, C> {
    /// Flushes the store to disk.
    pub async fn flush(&self) -> Result<()> {
        Ok(self.store.flush().await?)
    }

    /// Unpins a block from the store marking it ready for garbage collection.
    pub async fn unpin(&self, cid: &Cid) -> Result<()> {
        Ok(self.store.unpin(cid).await?)
    }
}

impl<S: MultiUserStore, H, C> GenericBlockBuilder<S, H, C> {
    /// Pins a block in the store.
    pub async fn pin(&self, cid: &Cid, path: &Path) -> Result<()> {
        Ok(self.store.pin(cid, path).await?)
    }
}

impl<S: AliasStore, H, C> GenericBlockBuilder<S, H, C> {
    /// Creates an alias for a cid.
    pub async fn alias(&self, alias: &[u8], cid: &Cid) -> Result<()> {
        Ok(self.store.alias(alias, cid, self.visibility).await?)
    }

    /// Removes an alias.
    pub async fn unalias(&self, alias: &[u8]) -> Result<()> {
        Ok(self.store.unalias(alias).await?)
    }

    /// Resolves an alias.
    pub async fn resolve(&self, alias: &[u8]) -> Result<Option<Cid>> {
        Ok(self.store.resolve(alias).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockBuilder, DagCbor, ipld};
    use crate::mem::MemStore;

    #[async_std::test]
    async fn test_block_builder() {
        let store = MemStore::default();
        let builder = BlockBuilder::new(store);

        let block1 = ipld!({
            "value": 42,
        });
        let cid1 = builder.insert(&block1).await.unwrap();
        let block1_2: Ipld = builder.get(&cid1).await.unwrap();
        assert_eq!(block1, block1_2);

        let block2 = ipld!({
            "name": cid1,
        });
        let cid2 = builder.insert(&block2).await.unwrap();
        let block2_2: Ipld = builder.get(&cid2).await.unwrap();
        assert_eq!(block2, block2_2);
    }

    #[async_std::test]
    async fn test_dag() {
        let store = MemStore::default();
        let builder = BlockBuilder::new(store);
        let ipld1 = ipld!({"a": 3});
        let cid = builder.insert(&ipld1).await.unwrap();
        let ipld2 = ipld!({"root": [{"child": &cid}]});
        let root = builder.insert(&ipld2).await.unwrap();
        let path = DagPath::new(&root, "root/0/child/a");
        assert_eq!(builder.get_path(&path).await.unwrap(), Ipld::Integer(3));
    }

    #[derive(Clone, DagCbor, Debug, Eq, PartialEq)]
    struct Identity {
        id: u64,
        name: String,
        age: u8,
    }

    #[async_std::test]
    #[cfg(feature = "crypto")]
    async fn test_block_builder_private() {
        let key = Key::from(b"private encryption key".to_vec());
        let store = MemStore::default();
        let builder = BlockBuilder::new_private(store, key);

        let identity = Identity {
            id: 0,
            name: "David Craven".into(),
            age: 26,
        };
        let cid = builder.insert(&identity).await.unwrap();
        let identity2 = builder.get(&cid).await.unwrap();
        assert_eq!(identity, identity2);
    }

    #[async_std::test]
    #[cfg(feature = "crypto")]
    async fn test_dag_private() {
        let key = Key::from(b"private encryption key".to_vec());
        let store = MemStore::default();
        let builder = BlockBuilder::new_private(store, key);
        let ipld1 = ipld!({"a": 3});
        let cid = builder.insert(&ipld1).await.unwrap();
        let ipld2 = ipld!({"root": [{"child": &cid}]});
        let root = builder.insert(&ipld2).await.unwrap();
        let path = DagPath::new(&root, "root/0/child/a");
        assert_eq!(builder.get_path(&path).await.unwrap(), Ipld::Integer(3));
    }
}
