//! SFrame (RFC 9605) with cipher suite `AES_128_CTR_HMAC_SHA256_80`, 0x0001:
//! the header, the key schedule and the AEAD, checked against the RFC's test
//! vectors.
//!
//! The suite is the RFC's short-tag one, for media: AES-128 in counter mode,
//! then HMAC-SHA256 over the result, cut to ten bytes. An Opus frame is about
//! sixty bytes, so the tag is a sixth of it rather than a quarter with GCM's
//! sixteen.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// `AES_128_CTR_HMAC_SHA256_80`.
pub const CIPHER_SUITE: u16 = 0x0001;
/// The AES key, the encryption half of an `sframe_key`.
const NKA: usize = 16;
/// HMAC-SHA256's output, the authentication half.
const NH: usize = 32;
const NK: usize = NKA + NH;
pub const NN: usize = 12;
/// The tag, in bytes.
pub const NT: usize = 10;
/// The longest header: a config byte, then an 8-byte KID and an 8-byte CTR.
pub const MAX_HEADER: usize = 17;

/// The header's KID and CTR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kid: u64,
    pub ctr: u64,
}

/// How many bytes `x` takes big-endian with no leading zeros, at least one.
fn len_of(x: u64) -> usize {
    (8 - (x.leading_zeros() as usize / 8)).max(1)
}

impl Header {
    /// Write it, as Figure 4 lays it out.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let (kid_inline, ctr_inline) = (self.kid < 8, self.ctr < 8);
        let mut config = 0u8;
        if kid_inline {
            config |= (self.kid as u8) << 4;
        } else {
            config |= 0x80 | ((len_of(self.kid) as u8 - 1) << 4);
        }
        if ctr_inline {
            config |= self.ctr as u8;
        } else {
            config |= 0x08 | (len_of(self.ctr) as u8 - 1);
        }
        out.push(config);
        if !kid_inline {
            out.extend_from_slice(&self.kid.to_be_bytes()[8 - len_of(self.kid)..]);
        }
        if !ctr_inline {
            out.extend_from_slice(&self.ctr.to_be_bytes()[8 - len_of(self.ctr)..]);
        }
    }

    /// Read one from the front of `bytes`: it, and how long it was.
    pub fn decode(bytes: &[u8]) -> Option<(Header, usize)> {
        let config = *bytes.first()?;
        let mut at = 1;
        let mut field = |extended: bool, low: u8| -> Option<u64> {
            if !extended {
                return Some(low as u64);
            }
            let n = low as usize + 1;
            let raw = bytes.get(at..at + n)?;
            at += n;
            Some(raw.iter().fold(0u64, |v, &b| v << 8 | b as u64))
        };
        let kid = field(config & 0x80 != 0, (config >> 4) & 0x07)?;
        let ctr = field(config & 0x08 != 0, config & 0x07)?;
        Some((Header { kid, ctr }, at))
    }
}

/// What one KID encrypts with: the AES key, the HMAC key and the salt.
#[derive(Clone)]
pub struct Keys {
    enc: Aes128,
    auth: [u8; NH],
    salt: [u8; NN],
}

impl Keys {
    /// `derive_key_salt`, then `derive_subkeys`.
    pub fn derive(kid: u64, base_key: &[u8]) -> Keys {
        let secret = Hkdf::<Sha256>::new(Some(&[]), base_key);
        let label = |what: &str| {
            let mut l = Vec::with_capacity(32);
            l.extend_from_slice(b"SFrame 1.0 Secret ");
            l.extend_from_slice(what.as_bytes());
            l.extend_from_slice(&kid.to_be_bytes());
            l.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
            l
        };
        let mut key = [0u8; NK];
        let mut salt = [0u8; NN];
        secret.expand(&label("key "), &mut key).expect("48 bytes is within HKDF's reach");
        secret.expand(&label("salt "), &mut salt).expect("12 bytes is within HKDF's reach");
        Keys::from_parts(&key, salt)
    }

    fn from_parts(key: &[u8; NK], salt: [u8; NN]) -> Keys {
        let enc = Aes128::new_from_slice(&key[..NKA]).expect("16 bytes");
        let mut auth = [0u8; NH];
        auth.copy_from_slice(&key[NKA..]);
        Keys { enc, auth, salt }
    }

    /// The salt XORed with the counter.
    fn nonce(&self, ctr: u64) -> [u8; NN] {
        let mut nonce = self.salt;
        for (n, c) in nonce[NN - 8..].iter_mut().zip(ctr.to_be_bytes()) {
            *n ^= c;
        }
        nonce
    }

    /// AES-CTR from `nonce ‖ 0u32`, in place — its own inverse.
    fn ctr(&self, nonce: &[u8; NN], data: &mut [u8]) {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let mut block = [0u8; 16];
            block[..NN].copy_from_slice(nonce);
            block[NN..].copy_from_slice(&(i as u32).to_be_bytes());
            let mut block = block.into();
            self.enc.encrypt_block(&mut block);
            for (d, k) in chunk.iter_mut().zip(block.iter()) {
                *d ^= k;
            }
        }
    }

    fn mac(&self, nonce: &[u8; NN], aad: &[&[u8]], ct: &[u8]) -> Hmac<Sha256> {
        let aad_len: usize = aad.iter().map(|a| a.len()).sum();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.auth).expect("any length");
        mac.update(&(aad_len as u64).to_be_bytes());
        mac.update(&(ct.len() as u64).to_be_bytes());
        mac.update(&(NT as u64).to_be_bytes());
        mac.update(nonce);
        for a in aad {
            mac.update(a);
        }
        mac.update(ct);
        mac
    }

    /// `AEAD.Encrypt` at counter `ctr`: `plaintext` becomes the ciphertext,
    /// and the tag is appended. `aad` is read as one string, in order.
    pub fn seal(&self, ctr: u64, aad: &[&[u8]], data: &mut Vec<u8>) {
        let nonce = self.nonce(ctr);
        self.ctr(&nonce, data);
        let tag = self.mac(&nonce, aad, data).finalize().into_bytes();
        data.extend_from_slice(&tag[..NT]);
    }

    /// `AEAD.Decrypt`: the plaintext, or `None` when the tag does not check
    /// out — compared in constant time.
    pub fn open(&self, ctr: u64, aad: &[&[u8]], sealed: &[u8]) -> Option<Vec<u8>> {
        let (ct, tag) = sealed.split_at(sealed.len().checked_sub(NT)?);
        let nonce = self.nonce(ctr);
        self.mac(&nonce, aad, ct).verify_truncated_left(tag).ok()?;
        let mut pt = ct.to_vec();
        self.ctr(&nonce, &mut pt);
        Some(pt)
    }
}

/// SFrame `encrypt`: the header, then the ciphertext and tag, with `metadata`
/// authenticated alongside.
pub fn encrypt(keys: &Keys, header: Header, metadata: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_HEADER + plaintext.len() + NT);
    header.encode(&mut out);
    let header_len = out.len();
    let mut body = plaintext.to_vec();
    keys.seal(header.ctr, &[&out[..header_len], metadata], &mut body);
    out.extend_from_slice(&body);
    out
}

/// SFrame `decrypt`, with the keys for the header's KID found by `keys_for`.
pub fn decrypt<'k>(
    sealed: &[u8],
    metadata: &[u8],
    keys_for: impl FnOnce(u64) -> Option<&'k Keys>,
) -> Result<(Header, Vec<u8>), Failure> {
    let (header, len) = Header::decode(sealed).ok_or(Failure::Malformed)?;
    let keys = keys_for(header.kid).ok_or(Failure::UnknownKey)?;
    let pt = keys.open(header.ctr, &[&sealed[..len], metadata], &sealed[len..]).ok_or(Failure::Forged)?;
    Ok((header, pt))
}

/// Why `decrypt` gave nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Malformed,
    UnknownKey,
    Forged,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 9605, C.1.
    #[test]
    fn headers_match_the_rfc() {
        let cases: &[(u64, u64, &str)] = &[
            (0, 0, "00"),
            (0, 1, "01"),
            (0, 0xff, "08ff"),
            (0, 0x100, "090100"),
            (0, 0xffff_ffff, "0bffffffff"),
            (0, 0xffff_ffff_ffff, "0dffffffffffff"),
            (0, u64::MAX, "0fffffffffffffffff"),
            (1, 0, "10"),
            (7, 7, "77"),
            (0xff, 0, "80ff"),
            (0x123, 0x4567, "9901234567"),
            (u64::MAX, u64::MAX, "ffffffffffffffffffffffffffffffffff"),
        ];
        for &(kid, ctr, want) in cases {
            let mut out = Vec::new();
            Header { kid, ctr }.encode(&mut out);
            assert_eq!(out, hex(want), "kid {kid:#x} ctr {ctr:#x}");
            assert_eq!(Header::decode(&out), Some((Header { kid, ctr }, out.len())));
        }
        assert_eq!(Header::decode(&hex("99012345")), None, "a CTR cut short");
        assert_eq!(Header::decode(&[]), None);
    }

    /// RFC 9605, C.2, suite 0x0001.
    #[test]
    fn the_aead_matches_the_rfc() {
        let key: [u8; NK] = hex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f 202122232425262728292a2b2c2d2e2f")
            .try_into()
            .unwrap();
        // The vector gives the nonce, not a salt and counter: a zero counter
        // makes the salt the nonce.
        let nonce: [u8; NN] = hex("101112131415161718191a1b").try_into().unwrap();
        let keys = Keys::from_parts(&key, nonce);
        let aad = hex("4945544620534672616d65205747");
        let pt = hex("64726166742d696574662d736672616d652d656e63");
        let ct = hex("6339af04ada1d064688a442b8dc69d5b6bfa40f4bef0583e8081069cc60705");
        let mut sealed = pt.clone();
        keys.seal(0, &[&aad], &mut sealed);
        assert_eq!(sealed, ct);
        assert_eq!(keys.open(0, &[&aad], &ct), Some(pt));
    }

    /// RFC 9605, C.4, suite 0x0001: key schedule, header and AEAD together.
    #[test]
    fn sframe_matches_the_rfc() {
        let keys = Keys::derive(0x123, &hex("000102030405060708090a0b0c0d0e0f"));
        assert_eq!(keys.salt.to_vec(), hex("50b29329a04dc0f184ac3168"));
        assert_eq!(keys.nonce(0x4567).to_vec(), hex("50b29329a04dc0f184ac740f"));
        let metadata = hex("4945544620534672616d65205747");
        let pt = hex("64726166742d696574662d736672616d652d656e63");
        let ct = hex("9901234567449408b6f490086165b9d6f62b24ae1a59a56486b4ae8ed036b88912e24f11");
        assert_eq!(encrypt(&keys, Header { kid: 0x123, ctr: 0x4567 }, &metadata, &pt), ct);
        let (header, out) = decrypt(&ct, &metadata, |kid| (kid == 0x123).then_some(&keys)).unwrap();
        assert_eq!((header, out), (Header { kid: 0x123, ctr: 0x4567 }, pt));
    }

    #[test]
    fn any_change_is_caught() {
        let keys = Keys::derive(5, b"room key");
        let sealed = encrypt(&keys, Header { kid: 5, ctr: 9 }, b"meta", b"hello there");
        for i in 0..sealed.len() {
            let mut bent = sealed.clone();
            bent[i] ^= 1;
            assert!(decrypt(&bent, b"meta", |_| Some(&keys)).is_err(), "byte {i} flipped went unnoticed");
        }
        assert_eq!(decrypt(&sealed, b"metA", |_| Some(&keys)).unwrap_err(), Failure::Forged, "metadata is covered");
        let other = Keys::derive(5, b"another key");
        assert_eq!(decrypt(&sealed, b"meta", |_| Some(&other)).unwrap_err(), Failure::Forged);
        assert_eq!(decrypt(&sealed, b"meta", |_| None).unwrap_err(), Failure::UnknownKey);
        assert_eq!(decrypt(&sealed[..5], b"meta", |_| Some(&keys)).unwrap_err(), Failure::Forged);
    }
}
