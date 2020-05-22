use crate::batch::Batch;
use crate::codec::{Decoder, Encoder, Encrypted, IpldDecoder};
use crate::path::DagPath;
use libipld::cid::Cid;
use libipld::codec::{Decode, Encode};
use libipld::error::Result;
use libipld::ipld::Ipld;
use libipld::store::{AliasStore, MultiUserStore, ReadonlyStore, Store, Visibility};
use std::path::Path;

/// Generic block builder for creating blocks.
pub struct BlockBuilder<S, C> {
    store: S,
    codec: C,
    visibility: Visibility,
}

impl<S, C> BlockBuilder<S, C> {
    /// Creates a builder for public blocks.
    pub fn new(store: S, codec: C) -> Self {
        Self {
            store,
            codec,
            visibility: Visibility::Public,
        }
    }

    /// Gets the visibility of the builder.
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Gets the store of the builder.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Gets the codec of the builder.
    pub fn codec(&self) -> &C {
        &self.codec
    }
}

impl<S, C: Encrypted> BlockBuilder<S, C> {
    /// Creates a builder for private blocks.
    pub fn new_private(store: S, codec: C) -> Self {
        Self {
            store,
            codec,
            visibility: Visibility::Private,
        }
    }
}

impl<S: ReadonlyStore, C: Decoder> BlockBuilder<S, C> {
    /// Returns the decoded block with cid.
    pub async fn get<D: Decode<C::Codec>>(&self, cid: &Cid) -> Result<D> {
        let data = self.store.get(cid).await?;
        self.codec.decode(cid, &data)
    }
}

impl<S: ReadonlyStore, C: IpldDecoder> BlockBuilder<S, C> {
    /// Returns the ipld representation of a block with cid.
    pub async fn get_ipld(&self, cid: &Cid) -> Result<Ipld> {
        let data = self.store.get(cid).await?;
        self.codec.decode_ipld(cid, &data)
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

impl<S: Store, C: Encoder + Clone> BlockBuilder<S, C> {
    /// Creates a new batch.
    pub fn create_batch(&self) -> Batch<C> {
        Batch::new(self.codec.clone())
    }

    /// Creates a new batch with capacity.
    pub fn create_batch_with_capacity(&self, capacity: usize) -> Batch<C> {
        Batch::with_capacity(self.codec.clone(), capacity)
    }

    /// Encodes and inserts a block into the store.
    pub async fn insert<E: Encode<C::Codec>>(&self, e: &E) -> Result<Cid> {
        let mut batch = self.create_batch();
        batch.insert(e)?;
        self.insert_batch(batch).await
    }

    /// Inserts a batch of blocks atomically pinning the last one.
    pub async fn insert_batch<T>(&self, batch: Batch<T>) -> Result<Cid> {
        Ok(self
            .store
            .insert_batch(batch.into_vec(), self.visibility)
            .await?)
    }
}

impl<S: Store, C> BlockBuilder<S, C> {
    /// Flushes the store to disk.
    pub async fn flush(&self) -> Result<()> {
        Ok(self.store.flush().await?)
    }

    /// Unpins a block from the store marking it ready for garbage collection.
    pub async fn unpin(&self, cid: &Cid) -> Result<()> {
        Ok(self.store.unpin(cid).await?)
    }
}

impl<S: MultiUserStore, C> BlockBuilder<S, C> {
    /// Pins a block in the store.
    pub async fn pin(&self, cid: &Cid, path: &Path) -> Result<()> {
        Ok(self.store.pin(cid, path).await?)
    }
}

impl<S: AliasStore, C> BlockBuilder<S, C> {
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
    #[cfg(feature = "crypto")]
    use crate::crypto::Key;
    use crate::Codec;
    #[cfg(feature = "crypto")]
    use crate::StrobeCodec;
    use libipld::mem::MemStore;
    use libipld::{ipld, DagCbor};

    #[async_std::test]
    async fn test_block_builder() {
        let store = MemStore::default();
        let codec = Codec::new();
        let builder = BlockBuilder::new(store, codec);

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
        let codec = Codec::new();
        let builder = BlockBuilder::new(store, codec);
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
        let codec = StrobeCodec::new(key);
        let builder = BlockBuilder::new_private(store, codec);

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
        let codec = StrobeCodec::new(key);
        let builder = BlockBuilder::new_private(store, codec);
        let ipld1 = ipld!({"a": 3});
        let cid = builder.insert(&ipld1).await.unwrap();
        let ipld2 = ipld!({"root": [{"child": &cid}]});
        let root = builder.insert(&ipld2).await.unwrap();
        let path = DagPath::new(&root, "root/0/child/a");
        assert_eq!(builder.get_path(&path).await.unwrap(), Ipld::Integer(3));
    }
}
