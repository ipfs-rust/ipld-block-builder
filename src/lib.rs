//! Block builder.
#![deny(missing_docs)]
#![deny(warnings)]
use crate::block::*;
use crate::codec::{Codec, Decode, Encode};
#[cfg(feature = "crypto")]
use crate::crypto::Key;
#[cfg(feature = "crypto")]
use crate::error::Error;
use crate::error::Result;
use crate::multihash::{Code, Multihasher};
use crate::path::Path as IpldPath;
#[cfg(feature = "crypto")]
use crate::raw::Raw;
use crate::store::{AliasStore, MultiUserStore, ReadonlyStore, Store, Visibility};
pub use libipld::*;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::path::Path;

#[cfg(feature = "crypto")]
mod crypto;

/// Path in a dag.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct DagPath<'a>(&'a Cid, IpldPath);

impl<'a> DagPath<'a> {
    /// Create a new dag path.
    pub fn new<T: Into<IpldPath>>(cid: &'a Cid, path: T) -> Self {
        Self(cid, path.into())
    }
}

impl<'a> From<&'a Cid> for DagPath<'a> {
    fn from(cid: &'a Cid) -> Self {
        Self(cid, Default::default())
    }
}

/// Default block builder.
/// #[cfg(feature = "dag-cbor")]
pub type BlockBuilder<S> =
    GenericBlockBuilder<S, crate::multihash::Blake2b256, crate::cbor::DagCbor>;

/// Generic block builder for creating blocks.
pub struct GenericBlockBuilder<S, H: Multihasher<Code>, C: Codec> {
    _marker: PhantomData<(H, C)>,
    store: S,
    visibility: Visibility,
    #[cfg(feature = "crypto")]
    key: Option<Key>,
}

impl<S, H: Multihasher<Code>, C: Codec> GenericBlockBuilder<S, H, C> {
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

impl<S, H: Multihasher<Code>, C: Codec> Deref for GenericBlockBuilder<S, H, C> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl<S, H: Multihasher<Code>, C: Codec> DerefMut for GenericBlockBuilder<S, H, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

impl<S: ReadonlyStore, H: Multihasher<Code>, C: Codec> GenericBlockBuilder<S, H, C> {
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
        let mut root = self.get_ipld(&path.0).await?;
        let mut ipld = &root;
        for segment in path.1.iter() {
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
    /// Encodes and inserts a block into the store.
    pub async fn insert<E: Encode<C>>(&self, e: &E) -> Result<Cid> {
        #[cfg(feature = "crypto")]
        let Block { cid, data } = if let Some(key) = self.key.as_ref() {
            let data = C::encode(e).map_err(|e| Error::CodecError(Box::new(e)))?;
            let ct =
                crypto::encrypt(key, C::CODE, &data).map_err(|e| Error::CodecError(Box::new(e)))?;
            encode::<Raw, H, _>(&ct)?
        } else {
            encode::<C, H, E>(e)?
        };
        #[cfg(not(feature = "crypto"))]
        let Block { cid, data } = encode::<C, H, E>(e)?;
        self.store.insert(&cid, data, self.visibility).await?;
        Ok(cid)
    }

    /// Flushes the store to disk.
    pub async fn flush(&self) -> Result<()> {
        Ok(self.store.flush().await?)
    }

    /// Unpins a block from the store marking it ready for garbage collection.
    pub async fn unpin(&self, cid: &Cid) -> Result<()> {
        Ok(self.store.unpin(cid).await?)
    }
}

impl<S: MultiUserStore, H: Multihasher<Code>, C: Codec> GenericBlockBuilder<S, H, C> {
    /// Pins a block in the store.
    pub async fn pin(&self, cid: &Cid, path: &Path) -> Result<()> {
        Ok(self.store.pin(cid, path).await?)
    }
}

impl<S: AliasStore, H: Multihasher<Code>, C: Codec> GenericBlockBuilder<S, H, C> {
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
    use crate::ipld;
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
