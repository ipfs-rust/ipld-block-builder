use crate::cid::Codec;
use core::convert::TryFrom;
use core::ops::Deref;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use strobe_rs::{SecParam, Strobe};
use thiserror::Error;
use zeroize::Zeroize;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub struct Key(Secret<Vec<u8>>);

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.expose_secret()
    }
}

impl From<Vec<u8>> for Key {
    fn from(key: Vec<u8>) -> Self {
        Self(Secret::new(key))
    }
}

impl From<&mut [u8]> for Key {
    fn from(key: &mut [u8]) -> Self {
        let secret = Self::from(key.to_vec());
        key.zeroize();
        secret
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("key needs to be at least 128 bits (16 bytes).")]
    KeyTooShort,
    #[error("cipher text needs to be larger than nonce + tag.")]
    CipherTooShort,
    #[error("mac integrity check failed.")]
    Integrity,
    #[error("failed to decode codec: {0}.")]
    Codec(Box<dyn std::error::Error + Send>),
}

/// Encrypts and MACs a plaintext message with a key of any size greater than 128 bits (16 bytes).
pub fn encrypt(key: &Key, codec: Codec, data: &[u8]) -> Result<Box<[u8]>, Error> {
    if key.len() < 16 {
        return Err(Error::KeyTooShort);
    }

    let mut buf = unsigned_varint::encode::u64_buffer();
    let codec = unsigned_varint::encode::u64(codec.into(), &mut buf);

    let mut s = Strobe::new(b"ipld-block-builder", SecParam::B128);

    // Absorb the key
    s.ad(key.deref(), false);

    // Create buffer.
    let mut buf = Vec::with_capacity(NONCE_LEN + codec.len() + data.len() + TAG_LEN);
    buf.resize(buf.capacity(), 0);
    //unsafe { buf.set_len(buf.capacity()) };

    // Generate 192-bit nonce and absorb it
    let nonce = &mut buf[..NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(nonce);
    s.ad(nonce, false);

    // Copy data to buffer and encrypt in place.
    let buf_len = buf.len();
    let ct = &mut buf[NONCE_LEN..(buf_len - TAG_LEN)];
    ct[..codec.len()].copy_from_slice(codec);
    ct[codec.len()..].copy_from_slice(data);
    s.send_enc(ct, false);

    // Add tag to verify message integrity.
    let mac = &mut buf[(buf_len - TAG_LEN)..];
    s.send_mac(mac, false);

    Ok(buf.into_boxed_slice())
}

/// Decrypts and checks the MAC of an encrypted message, given a key of any size greater
/// than 128 bits (16 bytes).
pub fn decrypt(key: &Key, mut buf: Box<[u8]>) -> Result<(Codec, Box<[u8]>), Error> {
    if key.len() < 16 {
        return Err(Error::KeyTooShort);
    }

    if buf.len() < TAG_LEN + NONCE_LEN {
        return Err(Error::CipherTooShort);
    }

    let mut s = Strobe::new(b"ipld-block-builder", SecParam::B128);
    let nonce = &buf[..NONCE_LEN];

    // Absorb the key
    s.ad(key.deref(), false);
    s.ad(nonce, false);

    let buf_len = buf.len();
    let data = &mut buf[NONCE_LEN..(buf_len - TAG_LEN)];
    s.recv_enc(data, false);

    let (raw_codec, data) =
        unsigned_varint::decode::u64(data).map_err(|e| Error::Codec(Box::new(e)))?;
    let codec = Codec::try_from(raw_codec).map_err(|e| Error::Codec(Box::new(e)))?;
    let data = data.to_vec().into_boxed_slice();

    let mac = &mut buf[(buf_len - TAG_LEN)..];
    s.recv_mac(mac, false).map_err(|_| Error::Integrity)?;

    Ok((codec, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_correctness() {
        let key = Key::from(vec![
            0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07,
            0x4b, 0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6,
            0x25, 0xd0, 0x0f, 0x75,
        ]);
        let plaintexts = [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &b"short"[..],
            &b"hello, how are you?"[..],
            &b"this is very short"[..],
            &b"this is very long though, like, very very long, should we test very very long\
           things here?"[..],
        ];

        for pt in plaintexts.iter() {
            let ct = encrypt(&key, Codec::Raw, pt).unwrap();
            let (codec, pt2) = decrypt(&key, ct).unwrap();
            assert_eq!(pt, &pt2.deref());
            assert_eq!(codec, Codec::Raw);
        }
    }
}
