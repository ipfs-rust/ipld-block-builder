#[cfg(feature = "crypto")]
use crate::crypto::Key;
use libipld::block::Block;
use libipld::cid::Cid;
use libipld::codec::{Codec, Decode, Encode};
#[cfg(feature = "crypto")]
use libipld::error::Error;
use libipld::error::Result;
use libipld::ipld::Ipld;
use libipld::multihash::{Code, Multihasher};
#[cfg(feature = "crypto")]
use libipld::raw::RawCodec;
use std::marker::PhantomData;
#[cfg(feature = "crypto")]
use std::sync::Arc;

/// Encoder trait.
pub trait Encoder {
    /// Ipld codec.
    type Codec: Codec;
    /// Hasher.
    type Hash: Multihasher<Code>;

    /// Encodes the value into a block.
    fn encode<T: Encode<Self::Codec>>(&self, value: &T) -> Result<Block>;
}

/// Decoder trait.
pub trait Decoder {
    /// Ipld codec.
    type Codec: Codec;

    /// Decodes the block into a value.
    fn decode<T: Decode<Self::Codec>>(&self, cid: &Cid, data: &[u8]) -> Result<T>;
}

/// Ipld decoder trait.
pub trait IpldDecoder {
    /// Decodes the block into `Ipld`.
    fn decode_ipld(&self, cid: &Cid, data: &[u8]) -> Result<Ipld>;
}

/// Marker trait for encrypted encoders.
pub trait Encrypted {}

/// Generic ipld codec.
#[derive(Clone, Default)]
pub struct GenericCodec<C, H> {
    _marker: PhantomData<(C, H)>,
}

impl<C, H> GenericCodec<C, H> {
    /// Create a new generic codec.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Codec, H: Multihasher<Code>> Encoder for GenericCodec<C, H> {
    type Codec = C;
    type Hash = H;

    fn encode<T: Encode<C>>(&self, value: &T) -> Result<Block> {
        libipld::block::encode::<C, H, T>(value)
    }
}

impl<C: Codec, H> Decoder for GenericCodec<C, H> {
    type Codec = C;

    fn decode<T: Decode<C>>(&self, cid: &Cid, data: &[u8]) -> Result<T> {
        libipld::block::decode::<C, T>(cid, data)
    }
}

impl<C, H> IpldDecoder for GenericCodec<C, H> {
    fn decode_ipld(&self, cid: &Cid, data: &[u8]) -> Result<Ipld> {
        libipld::block::decode_ipld(cid, data)
    }
}

/// Generic encrypted codec.
#[cfg(feature = "crypto")]
#[derive(Clone)]
pub struct GenericStrobeCodec<C, H> {
    _marker: PhantomData<(C, H)>,
    key: Arc<Key>,
}

#[cfg(feature = "crypto")]
impl<C, H> GenericStrobeCodec<C, H> {
    /// Creates a new generic strobe codec.
    pub fn new(key: Key) -> Self {
        Self {
            _marker: PhantomData,
            key: Arc::new(key),
        }
    }
}

#[cfg(feature = "crypto")]
impl<C: Codec, H: Multihasher<Code>> Encoder for GenericStrobeCodec<C, H> {
    type Codec = C;
    type Hash = H;

    fn encode<T: Encode<C>>(&self, value: &T) -> Result<Block> {
        let data = C::encode(value).map_err(|e| Error::CodecError(Box::new(e)))?;
        let ct = crate::crypto::encrypt(&self.key, C::CODE, &data)
            .map_err(|e| Error::CodecError(Box::new(e)))?;
        libipld::block::encode::<RawCodec, H, _>(&ct)
    }
}

#[cfg(feature = "crypto")]
impl<C: Codec, H> Decoder for GenericStrobeCodec<C, H> {
    type Codec = C;

    fn decode<T: Decode<C>>(&self, cid: &Cid, data: &[u8]) -> Result<T> {
        let ct = libipld::block::decode::<RawCodec, Box<[u8]>>(cid, data)?;
        let (codec, data) =
            crate::crypto::decrypt(&self.key, ct).map_err(|e| Error::CodecError(Box::new(e)))?;
        libipld::block::raw_decode::<C, T>(codec, &data)
    }
}

#[cfg(feature = "crypto")]
impl<C, H> IpldDecoder for GenericStrobeCodec<C, H> {
    fn decode_ipld(&self, cid: &Cid, data: &[u8]) -> Result<Ipld> {
        let ct = libipld::block::decode::<RawCodec, Box<[u8]>>(cid, data)?;
        let (codec, data) =
            crate::crypto::decrypt(&self.key, ct).map_err(|e| Error::CodecError(Box::new(e)))?;
        libipld::block::raw_decode_ipld(codec, &data)
    }
}

#[cfg(feature = "crypto")]
impl<C, H> Encrypted for GenericStrobeCodec<C, H> {}
