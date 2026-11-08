// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Per-block AEAD: each 4 KiB plaintext block becomes one record `nonce || ciphertext || tag`.
//!
//! The nonce is random per write, so rewriting a block never reuses a (key, nonce) pair in
//! practice. The caller supplies associated data that binds the block to its file and position.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::keys::random_bytes;

/// Plaintext bytes per block.
pub const BLOCK_SIZE: usize = 4096;
/// AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Bytes added to each block by the record framing.
pub const RECORD_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Size of a full on-disk record.
pub const RECORD_LEN: usize = BLOCK_SIZE + RECORD_OVERHEAD;

/// Encrypts `plaintext` (at most [`BLOCK_SIZE`] bytes) into a fresh record.
pub(crate) fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    debug_assert!(plaintext.len() <= BLOCK_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key).expect("key is 32 bytes");
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for in-range input");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Authenticates and decrypts a record. Returns `None` if the tag does not verify.
pub(crate) fn open(key: &[u8; 32], aad: &[u8], record: &[u8]) -> Option<Vec<u8>> {
    if record.len() < RECORD_OVERHEAD {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("key is 32 bytes");
    let (nonce, ct) = record.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}
