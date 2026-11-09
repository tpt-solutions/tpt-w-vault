// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! FUSE mount of an unlocked vault (Phase 6).
//!
//! The mount runs on a background thread, so the app can keep using the vault and unmount it
//! later. [`FuseMount`] starts it and unmounts it on drop.
//!
//! This is a thin adapter from `fuser` callbacks to [`tpt_vault_core::VaultTree`], which holds
//! the inode logic and is tested on every platform. Only this file depends on FUSE.
//!
//! Verified by `examples/mount_selftest.rs` on a Linux kernel, in the CI Linux job.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTEMPTY};
use tpt_vault_core::{EntryInfo, EntryKind, FsVault, VaultError, VaultTree};

/// How long the kernel may cache attributes and entries. Short, because another process can
/// change the vault only through this mount, but the cache must still not go stale for long.
const TTL: Duration = Duration::from_secs(1);

/// The FUSE filesystem for one unlocked vault.
pub struct VaultFs {
    tree: VaultTree<Arc<FsVault>>,
    uid: u32,
    gid: u32,
}

impl VaultFs {
    pub fn new(vault: Arc<FsVault>) -> Self {
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
        if let Some(new_size) = size {
            if let Err(e) = self.tree.truncate(ino, new_size) {
                return reply.error(errno(&e));
            }
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
        match self.tree.read(ino, offset.max(0) as u64, size as usize) {
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

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
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

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // Writes are already synced to disk when they complete, so there is nothing to flush.
        reply.ok();
    }
}

/// Serves `vault` at `mountpoint` until it is unmounted. Blocks the calling thread.
///
/// `AutoUnmount` asks FUSE to unmount when this process exits, including after a crash, so a
/// dead process does not leave a stale mount point behind.
pub fn serve(vault: Arc<FsVault>, mountpoint: &Path) -> io::Result<()> {
    let options = [
        MountOption::FSName("tpt-vault".into()),
        MountOption::RW,
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];
    fuser::mount2(VaultFs::new(vault), mountpoint, &options)
}

/// Whether `mountpoint` is in the kernel's mount table.
fn is_mounted(mountpoint: &Path) -> bool {
    let Some(target) = mountpoint.to_str() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split(' ').nth(4) == Some(target))
}

/// A vault mounted in the background. Dropping it unmounts the vault. If the drop cannot unmount
/// (for example because a file on the mount is still open), the mount stays up until the process
/// exits, and `AutoUnmount` then removes it.
pub struct FuseMount {
    mountpoint: PathBuf,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl FuseMount {
    /// Mounts `vault` at `mountpoint`, which must be an empty directory. Returns once the mount
    /// is listed in the kernel's mount table, or with the error that stopped it.
    pub fn start(vault: Arc<FsVault>, mountpoint: PathBuf) -> io::Result<Self> {
        let serving = mountpoint.clone();
        let thread = thread::spawn(move || serve(vault, &serving));
        let mut mount = FuseMount {
            mountpoint,
            thread: Some(thread),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if mount.thread.as_ref().is_some_and(|t| t.is_finished()) {
                // The server ended before the mount came up. Its error is the answer.
                let result = mount.thread.take().map(JoinHandle::join);
                return Err(match result {
                    Some(Ok(Err(e))) => e,
                    _ => io::Error::other("the FUSE server stopped before the mount came up"),
                });
            }
            if is_mounted(&mount.mountpoint) {
                return Ok(mount);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the FUSE mount did not appear in time",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Where the vault is mounted.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Unmounts the vault and waits for the server to stop.
    pub fn unmount(mut self) -> io::Result<()> {
        self.unmount_in_place()
    }

    fn unmount_in_place(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        // fusermount3 is the current helper; fusermount is the older name on some systems.
        let attempt = |program: &str| {
            Command::new(program)
                .arg("-u")
                .arg(&self.mountpoint)
                .status()
                .map(|s| s.success())
        };
        let unmounted =
            matches!(attempt("fusermount3"), Ok(true)) || matches!(attempt("fusermount"), Ok(true));
        if !unmounted {
            // Put the thread back, so a later drop can try again.
            self.thread = Some(thread);
            return Err(io::Error::other(format!(
                "could not unmount {}",
                self.mountpoint.display()
            )));
        }
        match thread.join() {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("the FUSE server panicked")),
        }
    }
}

impl Drop for FuseMount {
    fn drop(&mut self) {
        let _ = self.unmount_in_place();
    }
}
