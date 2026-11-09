// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Windows mount backend (Phase 5): shows an unlocked vault as a drive letter through WinFsp.
//!
//! [`WinFspMount::mount`] takes a shared handle to the vault. The app keeps its own handle, and
//! dropping a mount (or calling [`WinFspMount::unmount`]) removes the drive. If WinFsp is
//! missing, mounting fails with [`MountError::Unavailable`].

mod callbacks;
mod sys;

use std::{
    ffi::c_void,
    fmt,
    mem::size_of,
    ptr,
    sync::{Arc, Mutex},
};

use tpt_vault_core::{FsVault, VaultTree};

use callbacks::{Context, filetime_now};
use sys::{
    DISK_DEVICE_NAME, FLAG_CASE_PRESERVED_NAMES, FLAG_UNICODE_ON_DISK, FileSystem, Interface,
    NtStatus, STATUS_SUCCESS, VolumeParams, api,
};

/// IRP timeout default and capacity default, from WinFsp's `FspFsctlIrpTimeoutDefault` and
/// `FspFsctlIrpCapacityDefault`.
const IRP_TIMEOUT_DEFAULT_MS: u32 = 300_000;
const IRP_CAPACITY_DEFAULT: u32 = 1000;
const FILE_INFO_TIMEOUT_MS: u32 = 1000;

/// Why a mount failed.
#[derive(Debug)]
pub enum MountError {
    /// WinFsp is not installed or its DLL could not be loaded.
    Unavailable(String),
    /// The drive letter is not a letter.
    InvalidDrive(char),
    /// WinFsp returned an error status.
    Status {
        step: &'static str,
        status: NtStatus,
    },
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::Unavailable(why) => write!(f, "WinFsp is not available: {why}"),
            MountError::InvalidDrive(c) => write!(f, "{c:?} is not a drive letter"),
            MountError::Status { step, status } => {
                write!(
                    f,
                    "WinFsp failed to {step} (status 0x{:08X})",
                    *status as u32
                )
            }
        }
    }
}

impl std::error::Error for MountError {}

/// A vault mounted as a drive. Dropping it unmounts and discards the vault. Call
/// [`WinFspMount::unmount`] to get the vault back.
pub struct WinFspMount {
    mounted: Option<Mounted>,
}

struct Mounted {
    fs: *mut FileSystem,
    ctx: *mut Context,
}

// SAFETY: the pointers are owned by this value and only used through WinFsp's API, which is
// thread-safe. The `Context` they reach is protected by its own mutex.
unsafe impl Send for Mounted {}

static INTERFACE: Interface = Interface {
    get_volume_info: Some(callbacks::get_volume_info),
    set_volume_label: None,
    get_security_by_name: Some(callbacks::get_security_by_name),
    create: Some(callbacks::create),
    open: Some(callbacks::open),
    overwrite: Some(callbacks::overwrite),
    cleanup: Some(callbacks::cleanup),
    close: Some(callbacks::close),
    read: Some(callbacks::read),
    write: Some(callbacks::write),
    flush: Some(callbacks::flush),
    get_file_info: Some(callbacks::get_file_info),
    set_basic_info: Some(callbacks::set_basic_info),
    set_file_size: Some(callbacks::set_file_size),
    can_delete: Some(callbacks::can_delete),
    rename: Some(callbacks::rename),
    get_security: Some(callbacks::get_security),
    set_security: None,
    read_directory: Some(callbacks::read_directory),
    resolve_reparse_points: ptr::null(),
    get_reparse_point: ptr::null(),
    set_reparse_point: ptr::null(),
    delete_reparse_point: ptr::null(),
    get_stream_info: ptr::null(),
    get_dir_info_by_name: ptr::null(),
    control: ptr::null(),
    set_delete: Some(callbacks::set_delete),
    create_ex: ptr::null(),
    overwrite_ex: ptr::null(),
    get_ea: ptr::null(),
    set_ea: ptr::null(),
    obsolete0: ptr::null(),
    dispatcher_stopped: Some(callbacks::dispatcher_stopped),
    reserved: [ptr::null(); 31],
};

fn volume_params(now: u64) -> VolumeParams {
    // SAFETY: every field of `VolumeParams` is an integer or an array of integers, so the all-zero
    // bit pattern is valid. The non-zero fields are set below.
    let mut v: VolumeParams = unsafe { std::mem::zeroed() };
    v.version = size_of::<VolumeParams>() as u16;
    v.sector_size = 4096;
    v.sectors_per_allocation_unit = 1;
    v.max_component_length = 255;
    v.volume_creation_time = now;
    v.volume_serial_number = 0x7470_7476; // "tptv"
    v.irp_timeout = IRP_TIMEOUT_DEFAULT_MS;
    v.irp_capacity = IRP_CAPACITY_DEFAULT;
    v.file_info_timeout = FILE_INFO_TIMEOUT_MS;
    v.flags = FLAG_CASE_PRESERVED_NAMES | FLAG_UNICODE_ON_DISK;
    for (dst, src) in v.file_system_name.iter_mut().zip("tptvault".encode_utf16()) {
        *dst = src;
    }
    v
}

/// NUL-terminated UTF-16 for a WinFsp string argument.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Frees a mount's context. The vault itself stays alive through the app's own handle.
///
/// # Safety
/// `ctx` must come from `Box::into_raw` in [`WinFspMount::mount`], and must not be used again.
unsafe fn reclaim(ctx: *mut Context) {
    // SAFETY: per the contract above, the pointer is the unique owner of a live `Context`.
    drop(unsafe { Box::from_raw(ctx) });
}

impl WinFspMount {
    /// Mounts `vault` as drive `drive` (for example `'V'`). The caller keeps its handle to the
    /// vault, so the app can still read and write through it.
    pub fn mount(vault: Arc<FsVault>, drive: char) -> Result<Self, MountError> {
        if !drive.is_ascii_alphabetic() {
            return Err(MountError::InvalidDrive(drive));
        }
        let api = api().map_err(MountError::Unavailable)?;

        let now = filetime_now();
        let ctx = Box::into_raw(Box::new(Context {
            tree: Mutex::new(VaultTree::new(vault)),
            mount_time: now,
        }));

        let params = volume_params(now);
        let mut device = wide(DISK_DEVICE_NAME);
        let mut fs: *mut FileSystem = ptr::null_mut();
        // SAFETY: the device name, parameters and callback table are valid for the call.
        let status = unsafe { (api.create)(device.as_mut_ptr(), &params, &INTERFACE, &mut fs) };
        if status != STATUS_SUCCESS {
            // SAFETY: `ctx` was created above and is not referenced by WinFsp.
            unsafe { reclaim(ctx) };
            return Err(MountError::Status {
                step: "create the file system",
                status,
            });
        }

        // SAFETY: `fs` was returned by `FspFileSystemCreate` and is valid until deleted.
        unsafe { (*fs).user_context = ctx.cast::<c_void>() };

        let mut mount_point = wide(&format!("{}:", drive.to_ascii_uppercase()));
        // SAFETY: `fs` is valid, and the mount point is a NUL-terminated string.
        let status = unsafe { (api.set_mount_point)(fs, mount_point.as_mut_ptr()) };
        if status != STATUS_SUCCESS {
            return Err(Self::abandon(api, fs, ctx, "set the mount point", status));
        }

        // SAFETY: `fs` is valid. Zero asks WinFsp for its default number of threads.
        let status = unsafe { (api.start_dispatcher)(fs, 0) };
        if status != STATUS_SUCCESS {
            return Err(Self::abandon(api, fs, ctx, "start the dispatcher", status));
        }

        Ok(WinFspMount {
            mounted: Some(Mounted { fs, ctx }),
        })
    }

    /// Frees a file system whose setup failed.
    fn abandon(
        api: &sys::Api,
        fs: *mut FileSystem,
        ctx: *mut Context,
        step: &'static str,
        status: NtStatus,
    ) -> MountError {
        // SAFETY: the file system was created and its dispatcher never started, so no callbacks
        // can be running.
        unsafe { (api.delete)(fs) };
        // SAFETY: no callback can use `ctx` now.
        unsafe { reclaim(ctx) };
        MountError::Status { step, status }
    }

    /// Unmounts the drive. Open files on the drive are closed first.
    pub fn unmount(mut self) {
        self.teardown();
    }

    fn teardown(&mut self) {
        let Some(Mounted { fs, ctx }) = self.mounted.take() else {
            return;
        };
        let api = api().expect("WinFsp was loaded when this mount was created");
        // SAFETY: `fs` is the live file system from `mount`. Stopping the dispatcher waits for
        // in-flight callbacks, so nothing uses `ctx` after this.
        unsafe {
            (api.stop_dispatcher)(fs);
            (api.delete)(fs);
        }
        // SAFETY: the file system is deleted, so no callback can use `ctx`.
        unsafe { reclaim(ctx) };
    }
}

impl Drop for WinFspMount {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_map_to_vault_paths() {
        assert_eq!(callbacks::vault_path("\\").unwrap(), "");
        assert_eq!(
            callbacks::vault_path("\\docs\\plan.md").unwrap(),
            "docs/plan.md"
        );
        assert_eq!(callbacks::vault_path("\\a\\\\b\\").unwrap(), "a/b");
    }

    #[test]
    fn dot_segments_and_named_streams_are_refused() {
        assert!(callbacks::vault_path("\\..\\x").is_err());
        assert!(callbacks::vault_path("\\a\\.\\b").is_err());
        assert!(callbacks::vault_path("\\file.md:stream").is_err());
    }

    #[test]
    fn invalid_drive_letters_are_refused_before_loading_winfsp() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _code) = FsVault::create(
            dir.path(),
            b"mount-test",
            tpt_vault_core::KdfParams {
                log_n: 10,
                r: 8,
                p: 1,
            },
        )
        .unwrap();
        match WinFspMount::mount(Arc::new(vault), '1') {
            Err(MountError::InvalidDrive('1')) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("mounted with an invalid drive letter"),
        }
    }
}
