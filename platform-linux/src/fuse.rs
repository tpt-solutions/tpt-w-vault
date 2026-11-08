// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! FUSE mount of an unlocked vault (Phase 6).
//!
//! NOT COMPILED YET. This file is not declared as a module, so cargo ignores it. To enable it,
//! add `#[cfg(target_os = "linux")] mod fuse;` to `lib.rs`, and add `fuser` and `libc` as
//! Linux-only dependencies. Do this only after it has built on a Linux machine, so the Linux CI
//! job does not break.
//!
//! This is a thin adapter from `fuser` callbacks to [`tpt_vault_core::VaultTree`], which holds
//! the inode logic and is tested on every platform. Only this file depends on FUSE.
//!
//! Status: type-checked against the Linux target from Windows. Not yet mounted on a Linux
//! machine. The mount/unmount behaviour and crash cleanup are unverified.

use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTEMPTY};
use tpt_vault_core::{EntryInfo, EntryKind, FsVault, VaultError, VaultTree};

/// How long the kernel may cache attributes and entries. Short, because another process can
/// change the vault only through this mount, but the cache must still not go stale for long.
const TTL: Duration = Duration::from_secs(1);

/// The FUSE filesystem for one unlocked vault.
pub struct VaultFs {
    tree: VaultTree<FsVault>,
    uid: u32,
    gid: u32,
}

impl VaultFs {
    pub fn new(vault: FsVault) -> Self {
        // SAFETY: getuid and getgid are always safe to call and take no arguments.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        VaultFs {
            tree: VaultTree::new(vault),
            uid,
            gid,
        }
    }

    fn file_attr(&self, ino: u64, info: &EntryInfo) -> FileAttr {
        let now = SystemTime::now();
        let is_dir = info.kind == EntryKind::Directory;
        FileAttr {
            ino,
            size: info.size,
            blocks: info.size.div_ceil(512),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: if is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if is_dir { 0o700 } else { 0o600 },
            nlink: if is_dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Attributes for `ino`, or the errno to report.
    fn attr_for(&self, ino: u64) -> Result<FileAttr, i32> {
        let info = self.tree.getattr(ino).map_err(|e| errno(&e))?;
        Ok(self.file_attr(ino, &info))
    }
}

/// Maps a vault error to the errno a FUSE client expects.
fn errno(e: &VaultError) -> i32 {
    match e {
        VaultError::NotFound(_) => ENOENT,
        VaultError::AlreadyExists(_) => EEXIST,
        VaultError::NotADirectory(_) => ENOTDIR,
        VaultError::NotAFile(_) => EISDIR,
        VaultError::DirectoryNotEmpty(_) => ENOTEMPTY,
        VaultError::InvalidPath { .. } => EINVAL,
        VaultError::NameTooLong(_) => ENAMETOOLONG,
        _ => EIO,
    }
}

fn name_of(name: &OsStr) -> Result<&str, i32> {
    name.to_str().ok_or(EINVAL)
}

impl Filesystem for VaultFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let result = name_of(name).and_then(|n| {
            let (ino, info) = self.tree.lookup(parent, n).map_err(|e| errno(&e))?;
            Ok(self.file_attr(ino, &info))
        });
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(code) => reply.error(code),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.attr_for(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(code) => reply.error(code),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Only size changes are meaningful; mode, owner and times are fixed by the vault.
        if let Some(new_size) = size
            && let Err(e) = self.tree.truncate(ino, new_size)
        {
            return reply.error(errno(&e));
        }
        match self.attr_for(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(code) => reply.error(code),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let result = name_of(name).and_then(|n| {
            let ino = self.tree.mkdir(parent, n).map_err(|e| errno(&e))?;
            self.attr_for(ino)
        });
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(code) => reply.error(code),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let result = name_of(name).and_then(|n| {
            let ino = self.tree.create(parent, n).map_err(|e| errno(&e))?;
            self.attr_for(ino)
        });
        match result {
            Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
            Err(code) => reply.error(code),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let result = name_of(name).and_then(|n| self.tree.remove(parent, n).map_err(|e| errno(&e)));
        match result {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(code),
        }
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        // The vault removes files and empty directories with the same call.
        self.unlink(req, parent, name, reply);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            let from = name_of(name)?;
            let to = name_of(newname)?;
            self.tree
                .rename(parent, from, newparent, to)
                .map_err(|e| errno(&e))
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(code),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        // Handles are not tracked: each read and write opens the file by inode.
        match self.attr_for(ino) {
            Ok(_) => reply.opened(0, 0),
            Err(code) => reply.error(code),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        match self
            .tree
            .read(ino, offset.max(0) as u64, size as usize)
        {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        match self.tree.write(ino, offset.max(0) as u64, data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let parent = match self.tree.parent(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(errno(&e)),
        };
        let children = match self.tree.readdir(ino) {
            Ok(c) => c,
            Err(e) => return reply.error(errno(&e)),
        };
        // Offsets are positions in this listing: 1 is ".", 2 is "..", then the children.
        let mut all: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".into()),
            (parent, FileType::Directory, "..".into()),
        ];
        for (child, info) in children {
            let kind = if info.kind == EntryKind::Directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            all.push((child, kind, info.name));
        }
        for (i, (child, kind, name)) in all.into_iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(child, (i + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        // Writes are already synced to disk when they complete, so there is nothing to flush.
        reply.ok();
    }
}

/// Mounts the vault at `mountpoint` and serves requests until unmounted.
///
/// `AutoUnmount` asks FUSE to unmount when this process exits, including after a crash, so a
/// dead process does not leave a stale mount point behind.
pub fn mount(vault: FsVault, mountpoint: impl AsRef<Path>) -> std::io::Result<()> {
    let options = [
        MountOption::FSName("tpt-vault".into()),
        MountOption::RW,
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];
    fuser::mount2(VaultFs::new(vault), mountpoint, &options)
}
