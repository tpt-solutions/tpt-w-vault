// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! On-disk layout of one encrypted file.
//!
//! ```text
//! header:  "TPTV" (4) | file format version (1) | file id (16)          = 21 bytes
//! record i (for block i = 0, 1, ...): nonce (12) | ciphertext | tag (16)
//!          ciphertext is 4096 bytes except possibly the last record
//! ```
//!
//! Each record is authenticated with associated data `header || block index (u64 LE) || is_last`.
//! Binding the header and index stops block reordering and cross-file splicing. Binding
//! `is_last` stops silent truncation at a block boundary. Filenames are not bound, so renaming
//! a file never requires re-encrypting its contents.
//!
//! The plaintext length is implied by the record layout, so there is no length field to
//! update, and partial writes rewrite only the blocks they touch.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use crate::backend::{VaultFile, map_io};
use crate::block::{self, BLOCK_SIZE, RECORD_LEN, RECORD_OVERHEAD};
use crate::error::{Result, VaultError};
use crate::keys::{DerivedKeys, random_bytes};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"TPTV";
const FILE_FORMAT_VERSION: u8 = 1;
const FILE_ID_LEN: usize = 16;
/// Length of the file header.
pub const HEADER_LEN: usize = 4 + 1 + FILE_ID_LEN;

const HEADER_LEN_U64: u64 = HEADER_LEN as u64;
const RECORD_LEN_U64: u64 = RECORD_LEN as u64;
const BLOCK_SIZE_U64: u64 = BLOCK_SIZE as u64;
const OVERHEAD_U64: u64 = RECORD_OVERHEAD as u64;

/// Plaintext length implied by a file of `total` bytes on disk, or `None` if the length
/// cannot come from a valid layout.
pub(crate) fn plaintext_len_for_disk(total: u64) -> Option<u64> {
    let body = total.checked_sub(HEADER_LEN_U64)?;
    if body == 0 {
        return Some(0);
    }
    let blocks = body.div_ceil(RECORD_LEN_U64);
    let last_record = body - (blocks - 1) * RECORD_LEN_U64;
    if last_record <= OVERHEAD_U64 {
        return None;
    }
    Some((blocks - 1) * BLOCK_SIZE_U64 + (last_record - OVERHEAD_U64))
}

/// An open encrypted file. Holds the OS file, the shared keys, and the file's header.
pub struct FileHandle {
    file: File,
    keys: Arc<DerivedKeys>,
    header: [u8; HEADER_LEN],
    /// Plaintext path, for error messages.
    path: String,
}

impl FileHandle {
    /// Creates a new, empty encrypted file. Fails if `disk` already exists.
    pub(crate) fn create(disk: &Path, plain: &str, keys: Arc<DerivedKeys>) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(disk)
            .map_err(|e| map_io(plain, e))?;
        let file_id: [u8; FILE_ID_LEN] = random_bytes();
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = FILE_FORMAT_VERSION;
        header[5..].copy_from_slice(&file_id);
        let mut handle = FileHandle {
            file,
            keys,
            header,
            path: plain.to_owned(),
        };
        handle.file.write_all(&header)?;
        handle.file.sync_data()?;
        Ok(handle)
    }

    /// Opens an existing encrypted file and checks its header.
    pub(crate) fn open(disk: &Path, plain: &str, keys: Arc<DerivedKeys>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(disk)
            .map_err(|e| map_io(plain, e))?;
        let mut header = [0u8; HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|_| VaultError::Corrupt {
                path: plain.to_owned(),
                detail: "file is shorter than its header".into(),
            })?;
        if &header[..4] != MAGIC {
            return Err(VaultError::Corrupt {
                path: plain.to_owned(),
                detail: "missing tpt-vault file signature".into(),
            });
        }
        if header[4] != FILE_FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(u32::from(header[4])));
        }
        Ok(FileHandle {
            file,
            keys,
            header,
            path: plain.to_owned(),
        })
    }

    fn corrupt(&self, block: u64, detail: &str) -> VaultError {
        VaultError::Corrupt {
            path: self.path.clone(),
            detail: format!("block {block}: {detail}"),
        }
    }

    fn aad(&self, index: u64, is_last: bool) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 9);
        aad.extend_from_slice(&self.header);
        aad.extend_from_slice(&index.to_le_bytes());
        aad.push(u8::from(is_last));
        aad
    }

    fn total_on_disk(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Returns the plaintext length for an on-disk length, or a corruption error.
    fn plain_len_of(&self, total: u64) -> Result<u64> {
        plaintext_len_for_disk(total)
            .ok_or_else(|| self.corrupt(0, "file length is not a valid layout"))
    }

    /// Decrypts block `index`. `total` is the current on-disk length.
    fn read_block(&mut self, index: u64, total: u64) -> Result<Zeroizing<Vec<u8>>> {
        let body = total - HEADER_LEN_U64;
        let start = index * RECORD_LEN_U64;
        if start >= body {
            return Err(self.corrupt(index, "block lies beyond end of file"));
        }
        let rec_len = (body - start).min(RECORD_LEN_U64);
        if rec_len <= OVERHEAD_U64 {
            return Err(self.corrupt(index, "record is too short to hold a block"));
        }
        let is_last = start + RECORD_LEN_U64 >= body;
        let mut record = vec![0u8; rec_len as usize];
        self.file.seek(SeekFrom::Start(HEADER_LEN_U64 + start))?;
        self.file.read_exact(&mut record)?;
        let aad = self.aad(index, is_last);
        block::open(&self.keys.content, &aad, &record)
            .map(Zeroizing::new)
            .ok_or_else(|| self.corrupt(index, "failed authentication"))
    }

    /// Encrypts `plain` as block `index` (with the given last-block flag) and writes its record.
    fn write_block(&mut self, index: u64, is_last: bool, plain: &[u8]) -> Result<()> {
        let aad = self.aad(index, is_last);
        let record = block::seal(&self.keys.content, &aad, plain);
        self.file
            .seek(SeekFrom::Start(HEADER_LEN_U64 + index * RECORD_LEN_U64))?;
        self.file.write_all(&record)?;
        Ok(())
    }
}

impl VaultFile for FileHandle {
    fn size(&self) -> Result<u64> {
        let total = self.total_on_disk()?;
        self.plain_len_of(total)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let total = self.total_on_disk()?;
        let len = self.plain_len_of(total)?;
        if offset >= len || buf.is_empty() {
            return Ok(0);
        }
        let n = ((len - offset) as usize).min(buf.len());
        let end = offset + n as u64;
        let first = offset / BLOCK_SIZE_U64;
        let last = (end - 1) / BLOCK_SIZE_U64;
        let mut done = 0usize;
        for index in first..=last {
            let plain = self.read_block(index, total)?;
            let block_start = index * BLOCK_SIZE_U64;
            let from = (offset.max(block_start) - block_start) as usize;
            let to = ((end.min(block_start + plain.len() as u64)) - block_start) as usize;
            let chunk = &plain[from..to];
            buf[done..done + chunk.len()].copy_from_slice(chunk);
            done += chunk.len();
        }
        Ok(done)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let total = self.total_on_disk()?;
        let old_len = self.plain_len_of(total)?;
        let end = offset + data.len() as u64;
        let new_len = old_len.max(end);

        let last = (new_len - 1) / BLOCK_SIZE_U64;
        // Start at the old last block (its last-block flag may change) or at the first
        // touched block, whichever is earlier. An empty file starts at 0.
        let start = if old_len == 0 {
            0
        } else {
            let old_last = (old_len - 1) / BLOCK_SIZE_U64;
            old_last.min(offset / BLOCK_SIZE_U64)
        };

        for index in start..=last {
            let block_start = index * BLOCK_SIZE_U64;
            let block_len = if index == last {
                new_len - block_start
            } else {
                BLOCK_SIZE_U64
            } as usize;
            let mut plain = Zeroizing::new(vec![0u8; block_len]);

            let fully_overwritten = offset <= block_start && end >= block_start + block_len as u64;
            let had_old_data = old_len > block_start;
            if had_old_data && !fully_overwritten {
                let old = self.read_block(index, total)?;
                plain[..old.len()].copy_from_slice(&old);
            }

            let ov_start = offset.max(block_start);
            let ov_end = end.min(block_start + block_len as u64);
            if ov_start < ov_end {
                let dst = (ov_start - block_start) as usize..(ov_end - block_start) as usize;
                let src = (ov_start - offset) as usize..(ov_end - offset) as usize;
                plain[dst].copy_from_slice(&data[src]);
            }

            self.write_block(index, index == last, &plain)?;
        }
        self.file.sync_data()?;
        Ok(())
    }
}
