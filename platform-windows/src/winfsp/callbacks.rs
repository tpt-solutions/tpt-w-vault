// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! WinFsp callbacks, implemented over the vault's inode layer (`VaultTree`).
//!
//! WinFsp calls these from its dispatcher threads, so the tree sits behind a mutex. Each file
//! handle is the inode number cast to a pointer. Inodes are never reused within a mount, so a
//! stale handle fails cleanly. Every callback runs inside `catch_unwind`, so a panic becomes an
//! error status instead of unwinding into WinFsp's frames.

use std::{
    ffi::c_void,
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{Arc, Mutex},
};

use tpt_vault_core::{EntryInfo, EntryKind, FsVault, ROOT_INO, VaultError, VaultTree};

/// The inode table over the shared vault. The app keeps its own handle to the vault.
pub type Tree = VaultTree<Arc<FsVault>>;

use super::sys::{
    Boolean, DirInfoHeader, FileInfo, FileSystem, NtStatus, PWSTR, STATUS_SUCCESS, VolumeInfo, api,
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `CreateOptions` bit: the new object is a directory.
const FILE_DIRECTORY_FILE: u32 = 0x1;
/// `Cleanup` flag: delete the file now that its last handle is closing.
const CLEANUP_DELETE: u32 = 0x1;
const ALLOCATION_UNIT: u64 = 4096;
/// Seconds between the FILETIME epoch (1601) and the Unix epoch (1970).
const FILETIME_UNIX_OFFSET_SECS: u64 = 11_644_473_600;

// NTSTATUS values used here. Each matches the `windows` crate's constant of the same name.
const OBJECT_NAME_INVALID: NtStatus = 0xC000_0033_u32 as i32;
const OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034_u32 as i32;
const OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035_u32 as i32;
const FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BA_u32 as i32;
const NOT_A_DIRECTORY: NtStatus = 0xC000_0103_u32 as i32;
const DIRECTORY_NOT_EMPTY: NtStatus = 0xC000_0101_u32 as i32;
const END_OF_FILE: NtStatus = 0xC000_0011_u32 as i32;
const DISK_FULL: NtStatus = 0xC000_007F_u32 as i32;
const FILE_CORRUPT_ERROR: NtStatus = 0xC000_0102_u32 as i32;
const UNEXPECTED_IO_ERROR: NtStatus = 0xC000_00E9_u32 as i32;
const UNSUCCESSFUL: NtStatus = 0xC000_0001_u32 as i32;

/// State for one mounted vault. Leaked into the file system's user context while mounted.
pub struct Context {
    pub tree: Mutex<Tree>,
    /// Timestamp reported for every entry, since the vault does not store times.
    pub mount_time: u64,
}

/// Maps a core error to the NTSTATUS a Windows program expects.
pub fn status_of(e: &VaultError) -> NtStatus {
    match e {
        VaultError::NotFound(_) => OBJECT_NAME_NOT_FOUND,
        VaultError::AlreadyExists(_) => OBJECT_NAME_COLLISION,
        VaultError::DirectoryNotEmpty(_) => DIRECTORY_NOT_EMPTY,
        VaultError::InvalidPath { .. } | VaultError::NameTooLong(_) => OBJECT_NAME_INVALID,
        VaultError::NotAFile(_) => FILE_IS_A_DIRECTORY,
        VaultError::NotADirectory(_) => NOT_A_DIRECTORY,
        VaultError::WriteLimitReached => DISK_FULL,
        VaultError::Corrupt { .. } => FILE_CORRUPT_ERROR,
        VaultError::Io(_) => UNEXPECTED_IO_ERROR,
        _ => UNSUCCESSFUL,
    }
}

/// Converts a WinFsp path such as `\docs\plan.md` to a vault path such as `docs/plan.md`.
/// The root is `\` and maps to the empty string. Names with `:` are named streams, which the
/// vault does not store.
pub fn vault_path(win: &str) -> Result<String, NtStatus> {
    if win.contains(':') {
        return Err(OBJECT_NAME_INVALID);
    }
    let mut parts = Vec::new();
    for segment in win.split('\\') {
        match segment {
            "" => {}
            "." | ".." => return Err(OBJECT_NAME_INVALID),
            s => parts.push(s),
        }
    }
    Ok(parts.join("/"))
}

/// Splits a vault path into its parent path and final name. The root has no leaf.
fn split_leaf(path: &str) -> Option<(&str, &str)> {
    path.rsplit_once('/')
        .or(Some(("", path)))
        .filter(|(_, leaf)| !leaf.is_empty())
}

/// Finds the entry at `path`, ignoring case as Windows does, and returns its inode. The vault
/// stores names exactly as written, so the match is made against each directory listing.
fn resolve_ci(tree: &mut Tree, path: &str) -> Result<u64, NtStatus> {
    let mut ino = ROOT_INO;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        let children = tree.readdir(ino).map_err(|e| status_of(&e))?;
        let wanted = segment.to_lowercase();
        ino = children
            .into_iter()
            .find(|(_, info)| info.name.to_lowercase() == wanted)
            .map(|(child, _)| child)
            .ok_or(OBJECT_NAME_NOT_FOUND)?;
    }
    Ok(ino)
}

/// Removes the entry with inode `ino`, whatever its case.
fn remove_ino(tree: &mut Tree, ino: u64) -> Result<(), NtStatus> {
    let path = tree.path(ino).map_err(|e| status_of(&e))?;
    let (parent, leaf) = split_leaf(&path).ok_or(OBJECT_NAME_INVALID)?;
    let parent_ino = tree.resolve(parent).map_err(|e| status_of(&e))?;
    tree.remove(parent_ino, leaf).map_err(|e| status_of(&e))
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point at a NUL-terminated UTF-16 string that stays valid for the call.
unsafe fn read_wide(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller guarantees a NUL terminator within readable memory.
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// Current time as a FILETIME value.
pub fn filetime_now() -> u64 {
    let since_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (since_unix.as_secs() + FILETIME_UNIX_OFFSET_SECS) * 10_000_000
        + u64::from(since_unix.subsec_nanos()) / 100
}

fn context<'a>(fs: *mut FileSystem) -> &'a Context {
    // SAFETY: `fs` came from WinFsp and its user context was set to a live `Context` in
    // `WinFspMount::mount`, which keeps it alive until the file system is deleted.
    unsafe { &*((*fs).user_context as *const Context) }
}

fn handle_of(ino: *mut c_void) -> u64 {
    ino as u64
}

fn handle(ino: u64) -> *mut c_void {
    ino as *mut c_void
}

/// Fills WinFsp file information from an entry.
fn fill(ctx: &Context, ino: u64, info: &EntryInfo, out: &mut FileInfo) {
    let is_dir = info.kind == EntryKind::Directory;
    let size = if is_dir { 0 } else { info.size };
    *out = FileInfo {
        file_attributes: if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        },
        reparse_tag: 0,
        allocation_size: size.div_ceil(ALLOCATION_UNIT) * ALLOCATION_UNIT,
        file_size: size,
        creation_time: ctx.mount_time,
        last_access_time: ctx.mount_time,
        last_write_time: ctx.mount_time,
        change_time: ctx.mount_time,
        index_number: ino,
        hard_links: 0,
        ea_size: 0,
    };
}

/// Runs `f`, turning a panic into `default` so nothing unwinds into WinFsp.
fn run<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

/// Fails if `ino` is a directory that still has entries.
fn check_deletable(tree: &mut Tree, ino: u64) -> Result<(), NtStatus> {
    let info = tree.getattr(ino).map_err(|e| status_of(&e))?;
    if info.kind == EntryKind::Directory {
        let children = tree.readdir(ino).map_err(|e| status_of(&e))?;
        if !children.is_empty() {
            return Err(DIRECTORY_NOT_EMPTY);
        }
    }
    Ok(())
}

/// Builds one directory entry: the fixed header followed by the UTF-16 name. The storage is
/// 8-byte aligned, which the header needs.
fn build_entry(info: &FileInfo, name: &str) -> Vec<u64> {
    let name16: Vec<u16> = name.encode_utf16().collect();
    let size = size_of::<DirInfoHeader>() + name16.len() * 2;
    let mut bytes = vec![0u64; size.div_ceil(8)];
    let header = DirInfoHeader {
        size: size as u16,
        file_info: *info,
        padding: [0; 24],
    };
    // SAFETY: `bytes` has room for the header and the name, and is 8-byte aligned.
    unsafe {
        let base = bytes.as_mut_ptr().cast::<u8>();
        ptr::write(base.cast::<DirInfoHeader>(), header);
        ptr::copy_nonoverlapping(
            name16.as_ptr(),
            base.add(size_of::<DirInfoHeader>()).cast::<u16>(),
            name16.len(),
        );
    }
    bytes
}

pub unsafe extern "system" fn get_volume_info(
    _fs: *mut FileSystem,
    out: *mut VolumeInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        if out.is_null() {
            return UNSUCCESSFUL;
        }
        let label: Vec<u16> = "tpt-vault".encode_utf16().collect();
        let mut info = VolumeInfo {
            total_size: 1 << 40,
            free_size: 1 << 40,
            volume_label_length: (label.len() * 2) as u16,
            volume_label: [0; 32],
        };
        info.volume_label[..label.len()].copy_from_slice(&label);
        // SAFETY: WinFsp passes a valid output pointer.
        unsafe { ptr::write(out, info) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn get_security_by_name(
    fs: *mut FileSystem,
    name: PWSTR,
    attributes_out: *mut u32,
    _sd: *mut c_void,
    sd_size_out: *mut usize,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        // SAFETY: WinFsp passes a valid NUL-terminated name.
        let win = unsafe { read_wide(name) };
        let path = match vault_path(&win) {
            Ok(p) => p,
            Err(st) => return st,
        };
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        let ino = match resolve_ci(&mut tree, &path) {
            Ok(ino) => ino,
            Err(st) => return st,
        };
        let info = match tree.getattr(ino) {
            Ok(i) => i,
            Err(e) => return status_of(&e),
        };
        let mut fi = FileInfo::default();
        fill(ctx, ino, &info, &mut fi);
        // SAFETY: WinFsp passes valid output pointers. The vault has no security descriptors.
        unsafe {
            if !attributes_out.is_null() {
                *attributes_out = fi.file_attributes;
            }
            if !sd_size_out.is_null() {
                *sd_size_out = 0;
            }
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn create(
    fs: *mut FileSystem,
    name: PWSTR,
    create_options: u32,
    _access: u32,
    _attributes: u32,
    _sd: *mut c_void,
    _allocation: u64,
    file_context_out: *mut *mut c_void,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        // SAFETY: WinFsp passes a valid NUL-terminated name.
        let win = unsafe { read_wide(name) };
        let path = match vault_path(&win) {
            Ok(p) => p,
            Err(st) => return st,
        };
        let Some((parent, leaf)) = split_leaf(&path) else {
            return OBJECT_NAME_COLLISION;
        };
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        // Windows names are case-insensitive, so an existing entry under any case is a collision.
        if resolve_ci(&mut tree, &path).is_ok() {
            return OBJECT_NAME_COLLISION;
        }
        let parent_ino = match resolve_ci(&mut tree, parent) {
            Ok(i) => i,
            Err(st) => return st,
        };
        let result = if create_options & FILE_DIRECTORY_FILE != 0 {
            tree.mkdir(parent_ino, leaf)
        } else {
            tree.create(parent_ino, leaf)
        };
        let ino = match result {
            Ok(i) => i,
            Err(e) => return status_of(&e),
        };
        let info = match tree.getattr(ino) {
            Ok(i) => i,
            Err(e) => return status_of(&e),
        };
        // SAFETY: WinFsp passes valid output pointers.
        unsafe {
            if !file_context_out.is_null() {
                *file_context_out = handle(ino);
            }
            if !info_out.is_null() {
                fill(ctx, ino, &info, &mut *info_out);
            }
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn open(
    fs: *mut FileSystem,
    name: PWSTR,
    _create_options: u32,
    _access: u32,
    file_context_out: *mut *mut c_void,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        // SAFETY: WinFsp passes a valid NUL-terminated name.
        let win = unsafe { read_wide(name) };
        let path = match vault_path(&win) {
            Ok(p) => p,
            Err(st) => return st,
        };
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        let ino = match resolve_ci(&mut tree, &path) {
            Ok(i) => i,
            Err(st) => return st,
        };
        let info = match tree.getattr(ino) {
            Ok(i) => i,
            Err(e) => return status_of(&e),
        };
        // SAFETY: WinFsp passes valid output pointers.
        unsafe {
            if !file_context_out.is_null() {
                *file_context_out = handle(ino);
            }
            if !info_out.is_null() {
                fill(ctx, ino, &info, &mut *info_out);
            }
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn overwrite(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _attributes: u32,
    _replace_attributes: Boolean,
    _allocation: u64,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = tree.truncate(ino, 0) {
            return status_of(&e);
        }
        match tree.getattr(ino) {
            Ok(info) => {
                // SAFETY: WinFsp passes a valid output pointer.
                unsafe {
                    if !info_out.is_null() {
                        fill(ctx, ino, &info, &mut *info_out);
                    }
                }
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn cleanup(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _name: PWSTR,
    flags: u32,
) {
    run((), || {
        if flags & CLEANUP_DELETE == 0 {
            return;
        }
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        // Deletion failures cannot be reported from Cleanup. The entry stays if it cannot go.
        let Ok(path) = tree.path(ino) else { return };
        let Some((parent, leaf)) = split_leaf(&path) else {
            return;
        };
        if let Ok(parent_ino) = tree.resolve(parent) {
            let _ = tree.remove(parent_ino, leaf);
        }
    })
}

pub unsafe extern "system" fn close(_fs: *mut FileSystem, _file_context: *mut c_void) {
    // Handles hold no state beyond the inode number, so there is nothing to release.
}

pub unsafe extern "system" fn read(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    buffer: *mut c_void,
    offset: u64,
    length: u32,
    bytes_out: *mut u32,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        let data = match tree.read(ino, offset, length as usize) {
            Ok(d) => d,
            Err(e) => return status_of(&e),
        };
        if data.is_empty() && length > 0 {
            return END_OF_FILE;
        }
        // SAFETY: WinFsp provides a buffer of at least `length` bytes; `data` is at most that.
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), buffer.cast::<u8>(), data.len());
            if !bytes_out.is_null() {
                *bytes_out = data.len() as u32;
            }
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn write(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    buffer: *const c_void,
    offset: u64,
    length: u32,
    write_to_eof: Boolean,
    constrained_io: Boolean,
    bytes_out: *mut u32,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        let size = match tree.getattr(ino) {
            Ok(i) => i.size,
            Err(e) => return status_of(&e),
        };
        let offset = if write_to_eof != 0 { size } else { offset };
        let mut count = length as u64;
        if constrained_io != 0 {
            // Constrained I/O never extends the file.
            count = if offset >= size {
                0
            } else {
                count.min(size - offset)
            };
        }
        // SAFETY: WinFsp provides `length` readable bytes at `buffer`.
        let data = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), count as usize) };
        let written = if data.is_empty() {
            0
        } else {
            match tree.write(ino, offset, data) {
                Ok(n) => n,
                Err(e) => return status_of(&e),
            }
        };
        // SAFETY: WinFsp passes valid output pointers.
        unsafe {
            if !bytes_out.is_null() {
                *bytes_out = written as u32;
            }
        }
        if let Ok(info) = tree.getattr(ino) {
            // SAFETY: as above.
            unsafe {
                if !info_out.is_null() {
                    fill(ctx, ino, &info, &mut *info_out);
                }
            }
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn flush(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        // A null handle is a volume flush. Writes are synced as they happen, so there is nothing
        // more to do.
        if file_context.is_null() || info_out.is_null() {
            return STATUS_SUCCESS;
        }
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.getattr(ino) {
            Ok(info) => {
                // SAFETY: WinFsp passes a valid output pointer.
                unsafe { fill(ctx, ino, &info, &mut *info_out) };
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn get_file_info(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.getattr(ino) {
            Ok(info) => {
                // SAFETY: WinFsp passes a valid output pointer.
                unsafe { fill(ctx, ino, &info, &mut *info_out) };
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn set_basic_info(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _attributes: u32,
    _creation: u64,
    _last_access: u64,
    _last_write: u64,
    _change: u64,
    info_out: *mut FileInfo,
) -> NtStatus {
    // The vault stores no attributes or times, so the request is accepted and the current
    // information is returned.
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.getattr(ino) {
            Ok(info) => {
                // SAFETY: WinFsp passes a valid output pointer.
                unsafe {
                    if !info_out.is_null() {
                        fill(ctx, ino, &info, &mut *info_out);
                    }
                }
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn set_file_size(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    new_size: u64,
    allocation_only: Boolean,
    info_out: *mut FileInfo,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        if allocation_only == 0 {
            if let Err(e) = tree.truncate(ino, new_size) {
                return status_of(&e);
            }
        }
        match tree.getattr(ino) {
            Ok(info) => {
                // SAFETY: WinFsp passes a valid output pointer.
                unsafe {
                    if !info_out.is_null() {
                        fill(ctx, ino, &info, &mut *info_out);
                    }
                }
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn can_delete(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _name: PWSTR,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        match check_deletable(&mut tree, handle_of(file_context)) {
            Ok(()) => STATUS_SUCCESS,
            Err(st) => st,
        }
    })
}

pub unsafe extern "system" fn set_delete(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _name: PWSTR,
    delete: Boolean,
) -> NtStatus {
    // The removal itself happens in `cleanup`, once the last handle closes. Here only the check
    // that the entry may go is made.
    run(UNSUCCESSFUL, || {
        if delete == 0 {
            return STATUS_SUCCESS;
        }
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
        match check_deletable(&mut tree, handle_of(file_context)) {
            Ok(()) => STATUS_SUCCESS,
            Err(st) => st,
        }
    })
}

pub unsafe extern "system" fn rename(
    fs: *mut FileSystem,
    _file_context: *mut c_void,
    name: PWSTR,
    new_name: PWSTR,
    replace_if_exists: Boolean,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        // SAFETY: WinFsp passes valid NUL-terminated names.
        let (from_win, to_win) = unsafe { (read_wide(name), read_wide(new_name)) };
        let (from, to) = match (vault_path(&from_win), vault_path(&to_win)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(st), _) | (_, Err(st)) => return st,
        };
        let ctx = context(fs);
        let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());

        // Work from the entry's stored name, so the case the vault has is the one renamed.
        let from_ino = match resolve_ci(&mut tree, &from) {
            Ok(i) => i,
            Err(st) => return st,
        };
        let stored_from = match tree.path(from_ino) {
            Ok(p) => p,
            Err(e) => return status_of(&e),
        };
        let (Some((from_parent, from_leaf)), Some((to_parent, to_leaf))) =
            (split_leaf(&stored_from), split_leaf(&to))
        else {
            return OBJECT_NAME_INVALID;
        };
        let from_dir = match resolve_ci(&mut tree, from_parent) {
            Ok(i) => i,
            Err(st) => return st,
        };
        let to_dir = match resolve_ci(&mut tree, to_parent) {
            Ok(i) => i,
            Err(st) => return st,
        };

        // A different entry at the destination, under any case, is refused or replaced.
        if let Ok(existing) = resolve_ci(&mut tree, &to) {
            if existing != from_ino {
                if replace_if_exists == 0 {
                    return OBJECT_NAME_COLLISION;
                }
                if let Err(st) = remove_ino(&mut tree, existing) {
                    return st;
                }
            }
        }
        match tree.rename(from_dir, from_leaf, to_dir, to_leaf) {
            Ok(()) => STATUS_SUCCESS,
            Err(e) => status_of(&e),
        }
    })
}

pub unsafe extern "system" fn get_security(
    _fs: *mut FileSystem,
    _file_context: *mut c_void,
    _sd: *mut c_void,
    sd_size_out: *mut usize,
) -> NtStatus {
    // No security descriptors are stored. Report an empty one.
    run(UNSUCCESSFUL, || {
        if !sd_size_out.is_null() {
            // SAFETY: WinFsp passes a valid output pointer.
            unsafe { *sd_size_out = 0 };
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn read_directory(
    fs: *mut FileSystem,
    file_context: *mut c_void,
    _pattern: PWSTR,
    marker: PWSTR,
    buffer: *mut c_void,
    length: u32,
    bytes_out: *mut u32,
) -> NtStatus {
    run(UNSUCCESSFUL, || {
        let ctx = context(fs);
        let ino = handle_of(file_context);
        let api = match api() {
            Ok(a) => a,
            Err(_) => return UNSUCCESSFUL,
        };

        // Gather the listing: "." and ".." first, then the children.
        let mut entries: Vec<(String, FileInfo)> = Vec::new();
        {
            let mut tree = ctx.tree.lock().unwrap_or_else(|p| p.into_inner());
            let own = match tree.getattr(ino) {
                Ok(i) => i,
                Err(e) => return status_of(&e),
            };
            let mut fi = FileInfo::default();
            fill(ctx, ino, &own, &mut fi);
            entries.push((".".into(), fi));
            let parent = tree.parent(ino).unwrap_or(ROOT_INO);
            if let Ok(pinfo) = tree.getattr(parent) {
                fill(ctx, parent, &pinfo, &mut fi);
            }
            entries.push(("..".into(), fi));
            let children = match tree.readdir(ino) {
                Ok(c) => c,
                Err(e) => return status_of(&e),
            };
            for (child, info) in children {
                let mut fi = FileInfo::default();
                fill(ctx, child, &info, &mut fi);
                entries.push((info.name.clone(), fi));
            }
        }

        // Directory buffering: fill a fresh buffer on every call, then copy out from the marker.
        // Each call is independent, so a listing that changes between calls is still consistent
        // with what each call returns.
        let mut dir_buffer: *mut c_void = ptr::null_mut();
        let mut status = STATUS_SUCCESS;
        let reset: Boolean = u8::from(marker.is_null());
        // SAFETY: the buffer pointer and status are valid locals for the duration of each call.
        let acquired =
            unsafe { (api.acquire_dir_buffer)(&mut dir_buffer, reset, &mut status) } != 0;
        if acquired {
            for (name, info) in &entries {
                let mut entry = build_entry(info, name);
                let mut fill_status = STATUS_SUCCESS;
                // SAFETY: `entry` holds one complete directory record, which WinFsp copies.
                let ok = unsafe {
                    (api.fill_dir_buffer)(
                        &mut dir_buffer,
                        entry.as_mut_ptr().cast::<DirInfoHeader>(),
                        &mut fill_status,
                    )
                } != 0;
                if !ok {
                    // The buffer is full. The rest comes on the next call.
                    break;
                }
            }
            // SAFETY: the buffer was acquired above.
            unsafe { (api.release_dir_buffer)(&mut dir_buffer) };
        } else if status != STATUS_SUCCESS {
            return status;
        }

        // SAFETY: the buffer is valid and `buffer`/`bytes_out` come from WinFsp.
        unsafe {
            (api.read_dir_buffer)(&mut dir_buffer, marker, buffer, length, bytes_out);
            (api.delete_dir_buffer)(&mut dir_buffer);
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn dispatcher_stopped(_fs: *mut FileSystem, _normally: Boolean) {}
