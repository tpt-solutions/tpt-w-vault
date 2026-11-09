// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Raw WinFsp interface for the 64-bit driver: struct layouts, callback table, and entry points.
//!
//! The layouts follow WinFsp's public user-mode API. Each struct has a size test below that
//! matches the sizes WinFsp asserts in its own header, so a layout mistake fails the build's
//! tests rather than corrupting memory at run time. The DLL is loaded at run time, so the app
//! starts and reports "WinFsp not installed" when the driver is missing.

#![allow(non_snake_case, dead_code)]

use std::{ffi::c_void, sync::OnceLock};

pub type NtStatus = i32;
/// Pointer to a NUL-terminated UTF-16 string. The name follows WinFsp's own spelling.
#[allow(clippy::upper_case_acronyms)]
pub type PWSTR = *mut u16;
pub type Boolean = u8;

pub const STATUS_SUCCESS: NtStatus = 0;

/// Opaque prefix of `FSP_FILE_SYSTEM`. Only the version and the user-context pointer are used,
/// and they sit at the same offsets as in WinFsp's structure.
#[repr(C)]
pub struct FileSystem {
    pub version: u16,
    pub user_context: *mut c_void,
}

/// Volume parameters (`FSP_FSCTL_VOLUME_PARAMS`, 504 bytes). WinFsp's bit-field words are kept as
/// plain `u32` and set through the `FLAG_*` constants.
#[repr(C)]
pub struct VolumeParams {
    pub version: u16,
    pub sector_size: u16,
    pub sectors_per_allocation_unit: u16,
    pub max_component_length: u16,
    pub volume_creation_time: u64,
    pub volume_serial_number: u32,
    pub transact_timeout: u32,
    pub irp_timeout: u32,
    pub irp_capacity: u32,
    pub file_info_timeout: u32,
    /// Bit-field word 1: attribute flags, then kernel and user-mode flags.
    pub flags: u32,
    pub prefix: [u16; 192],
    pub file_system_name: [u16; 16],
    /// Bit-field word 2, for the version 1 fields.
    pub flags2: u32,
    pub volume_info_timeout: u32,
    pub dir_info_timeout: u32,
    pub security_timeout: u32,
    pub stream_info_timeout: u32,
    pub ea_timeout: u32,
    pub fsext_control_code: u32,
    pub reserved32: [u32; 1],
    pub reserved64: [u64; 2],
}

/// Bits in `VolumeParams::flags`.
pub const FLAG_CASE_PRESERVED_NAMES: u32 = 1 << 1;
pub const FLAG_UNICODE_ON_DISK: u32 = 1 << 2;

/// File information (`FSP_FSCTL_FILE_INFO`, 72 bytes). Times are FILETIME values.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FileInfo {
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub allocation_size: u64,
    pub file_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
    pub hard_links: u32,
    pub ea_size: u32,
}

/// Volume information (`FSP_FSCTL_VOLUME_INFO`, 88 bytes).
#[repr(C)]
pub struct VolumeInfo {
    pub total_size: u64,
    pub free_size: u64,
    pub volume_label_length: u16,
    pub volume_label: [u16; 32],
}

/// Fixed part of a directory entry (`FSP_FSCTL_DIR_INFO`, 104 bytes). The UTF-16 name follows it
/// directly.
#[repr(C)]
pub struct DirInfoHeader {
    pub size: u16,
    pub file_info: FileInfo,
    pub padding: [u8; 24],
}

pub type GetVolumeInfoFn = unsafe extern "system" fn(*mut FileSystem, *mut VolumeInfo) -> NtStatus;
pub type SetVolumeLabelFn =
    unsafe extern "system" fn(*mut FileSystem, PWSTR, *mut VolumeInfo) -> NtStatus;
pub type GetSecurityByNameFn = unsafe extern "system" fn(
    *mut FileSystem,
    PWSTR,
    *mut u32,
    *mut c_void,
    *mut usize,
) -> NtStatus;
pub type CreateFn = unsafe extern "system" fn(
    *mut FileSystem,
    PWSTR,
    u32,
    u32,
    u32,
    *mut c_void,
    u64,
    *mut *mut c_void,
    *mut FileInfo,
) -> NtStatus;
pub type OpenFn = unsafe extern "system" fn(
    *mut FileSystem,
    PWSTR,
    u32,
    u32,
    *mut *mut c_void,
    *mut FileInfo,
) -> NtStatus;
pub type OverwriteFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    u32,
    Boolean,
    u64,
    *mut FileInfo,
) -> NtStatus;
pub type CleanupFn = unsafe extern "system" fn(*mut FileSystem, *mut c_void, PWSTR, u32);
pub type CloseFn = unsafe extern "system" fn(*mut FileSystem, *mut c_void);
pub type ReadFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    *mut c_void,
    u64,
    u32,
    *mut u32,
) -> NtStatus;
pub type WriteFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    *const c_void,
    u64,
    u32,
    Boolean,
    Boolean,
    *mut u32,
    *mut FileInfo,
) -> NtStatus;
pub type FlushFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, *mut FileInfo) -> NtStatus;
pub type GetFileInfoFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, *mut FileInfo) -> NtStatus;
pub type SetBasicInfoFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    u32,
    u64,
    u64,
    u64,
    u64,
    *mut FileInfo,
) -> NtStatus;
pub type SetFileSizeFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    u64,
    Boolean,
    *mut FileInfo,
) -> NtStatus;
pub type CanDeleteFn = unsafe extern "system" fn(*mut FileSystem, *mut c_void, PWSTR) -> NtStatus;
pub type RenameFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, PWSTR, PWSTR, Boolean) -> NtStatus;
pub type GetSecurityFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, *mut c_void, *mut usize) -> NtStatus;
pub type SetSecurityFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, u32, *mut c_void) -> NtStatus;
pub type ReadDirectoryFn = unsafe extern "system" fn(
    *mut FileSystem,
    *mut c_void,
    PWSTR,
    PWSTR,
    *mut c_void,
    u32,
    *mut u32,
) -> NtStatus;
pub type SetDeleteFn =
    unsafe extern "system" fn(*mut FileSystem, *mut c_void, PWSTR, Boolean) -> NtStatus;
pub type DispatcherStoppedFn = unsafe extern "system" fn(*mut FileSystem, Boolean);

/// The file system callback table (`FSP_FILE_SYSTEM_INTERFACE`). Callbacks that this crate does
/// not implement are null. WinFsp answers those operations itself or with an error.
#[repr(C)]
pub struct Interface {
    pub get_volume_info: Option<GetVolumeInfoFn>,
    pub set_volume_label: Option<SetVolumeLabelFn>,
    pub get_security_by_name: Option<GetSecurityByNameFn>,
    pub create: Option<CreateFn>,
    pub open: Option<OpenFn>,
    pub overwrite: Option<OverwriteFn>,
    pub cleanup: Option<CleanupFn>,
    pub close: Option<CloseFn>,
    pub read: Option<ReadFn>,
    pub write: Option<WriteFn>,
    pub flush: Option<FlushFn>,
    pub get_file_info: Option<GetFileInfoFn>,
    pub set_basic_info: Option<SetBasicInfoFn>,
    pub set_file_size: Option<SetFileSizeFn>,
    pub can_delete: Option<CanDeleteFn>,
    pub rename: Option<RenameFn>,
    pub get_security: Option<GetSecurityFn>,
    pub set_security: Option<SetSecurityFn>,
    pub read_directory: Option<ReadDirectoryFn>,
    pub resolve_reparse_points: *const c_void,
    pub get_reparse_point: *const c_void,
    pub set_reparse_point: *const c_void,
    pub delete_reparse_point: *const c_void,
    pub get_stream_info: *const c_void,
    pub get_dir_info_by_name: *const c_void,
    pub control: *const c_void,
    pub set_delete: Option<SetDeleteFn>,
    pub create_ex: *const c_void,
    pub overwrite_ex: *const c_void,
    pub get_ea: *const c_void,
    pub set_ea: *const c_void,
    pub obsolete0: *const c_void,
    pub dispatcher_stopped: Option<DispatcherStoppedFn>,
    pub reserved: [*const c_void; 31],
}

// The table holds only function pointers and nulls, so it is safe to share between threads.
unsafe impl Sync for Interface {}

pub type CreateFsFn = unsafe extern "system" fn(
    PWSTR,
    *const VolumeParams,
    *const Interface,
    *mut *mut FileSystem,
) -> NtStatus;
pub type DeleteFsFn = unsafe extern "system" fn(*mut FileSystem);
pub type SetMountPointFn = unsafe extern "system" fn(*mut FileSystem, PWSTR) -> NtStatus;
pub type StartDispatcherFn = unsafe extern "system" fn(*mut FileSystem, u32) -> NtStatus;
pub type StopDispatcherFn = unsafe extern "system" fn(*mut FileSystem);
pub type AcquireDirBufferFn =
    unsafe extern "system" fn(*mut *mut c_void, Boolean, *mut NtStatus) -> Boolean;
pub type FillDirBufferFn =
    unsafe extern "system" fn(*mut *mut c_void, *mut DirInfoHeader, *mut NtStatus) -> Boolean;
pub type ReleaseDirBufferFn = unsafe extern "system" fn(*mut *mut c_void);
pub type ReadDirBufferFn =
    unsafe extern "system" fn(*mut *mut c_void, PWSTR, *mut c_void, u32, *mut u32);
pub type DeleteDirBufferFn = unsafe extern "system" fn(*mut *mut c_void);

/// Entry points resolved from the WinFsp DLL.
pub struct Api {
    _library: libloading::Library,
    pub create: CreateFsFn,
    pub delete: DeleteFsFn,
    pub set_mount_point: SetMountPointFn,
    pub start_dispatcher: StartDispatcherFn,
    pub stop_dispatcher: StopDispatcherFn,
    pub acquire_dir_buffer: AcquireDirBufferFn,
    pub fill_dir_buffer: FillDirBufferFn,
    pub release_dir_buffer: ReleaseDirBufferFn,
    pub read_dir_buffer: ReadDirBufferFn,
    pub delete_dir_buffer: DeleteDirBufferFn,
}

/// The WinFsp device for local disks (`FSP_FSCTL_DISK_DEVICE_NAME`).
pub const DISK_DEVICE_NAME: &str = "WinFsp.Disk";

static API: OnceLock<Result<Api, String>> = OnceLock::new();

/// Loads the WinFsp DLL on first use. Returns why it could not be loaded.
pub fn api() -> Result<&'static Api, String> {
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    let path = dll_path();
    // SAFETY: loading the DLL runs its initialization code, which WinFsp's installer provides.
    let library = unsafe { libloading::Library::new(&path) }
        .map_err(|e| format!("could not load {}: {e}", path.display()))?;
    unsafe fn symbol<T: Copy>(lib: &libloading::Library, name: &[u8]) -> Result<T, String> {
        // SAFETY: the caller names the signature for each symbol in this file.
        let sym: libloading::Symbol<T> = unsafe { lib.get(name) }
            .map_err(|e| format!("missing {}: {e}", String::from_utf8_lossy(name)))?;
        Ok(*sym)
    }
    // SAFETY: each type matches the WinFsp declaration of the named export.
    unsafe {
        Ok(Api {
            create: symbol(&library, b"FspFileSystemCreate\0")?,
            delete: symbol(&library, b"FspFileSystemDelete\0")?,
            set_mount_point: symbol(&library, b"FspFileSystemSetMountPoint\0")?,
            start_dispatcher: symbol(&library, b"FspFileSystemStartDispatcher\0")?,
            stop_dispatcher: symbol(&library, b"FspFileSystemStopDispatcher\0")?,
            acquire_dir_buffer: symbol(&library, b"FspFileSystemAcquireDirectoryBuffer\0")?,
            fill_dir_buffer: symbol(&library, b"FspFileSystemFillDirectoryBuffer\0")?,
            release_dir_buffer: symbol(&library, b"FspFileSystemReleaseDirectoryBuffer\0")?,
            read_dir_buffer: symbol(&library, b"FspFileSystemReadDirectoryBuffer\0")?,
            delete_dir_buffer: symbol(&library, b"FspFileSystemDeleteDirectoryBuffer\0")?,
            _library: library,
        })
    }
}

/// Where the 64-bit WinFsp DLL is installed. The install directory is recorded in the registry,
/// so the DLL is found even when its directory is not on `PATH`.
fn dll_path() -> std::path::PathBuf {
    let install = registry_install_dir()
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files (x86)\WinFsp"));
    install.join("bin").join("winfsp-x64.dll")
}

fn registry_install_dir() -> Option<std::path::PathBuf> {
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    use windows::core::w;

    let mut buf = [0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: the buffer and the byte count describe the same writable array.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\WOW6432Node\WinFsp"),
            w!("InstallDir"),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    }
    let chars = (size as usize / 2).saturating_sub(1);
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &buf[..chars],
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // Sizes that WinFsp's header asserts (x64). A mismatch means the layout is wrong.
    #[test]
    fn struct_sizes_match_winfsp() {
        assert_eq!(size_of::<VolumeParams>(), 504);
        assert_eq!(size_of::<FileInfo>(), 72);
        assert_eq!(size_of::<VolumeInfo>(), 88);
        assert_eq!(size_of::<DirInfoHeader>(), 104);
    }

    #[test]
    fn volume_params_field_offsets_match_winfsp() {
        assert_eq!(offset_of!(VolumeParams, volume_creation_time), 8);
        assert_eq!(offset_of!(VolumeParams, flags), 36);
        assert_eq!(offset_of!(VolumeParams, prefix), 40);
        assert_eq!(offset_of!(VolumeParams, file_system_name), 424);
        assert_eq!(offset_of!(VolumeParams, flags2), 456);
        assert_eq!(offset_of!(VolumeParams, reserved64), 488);
    }

    #[test]
    fn dir_info_name_follows_the_fixed_header() {
        assert_eq!(size_of::<DirInfoHeader>(), 104);
        assert_eq!(offset_of!(DirInfoHeader, file_info), 8);
    }

    #[test]
    fn interface_table_has_the_winfsp_entry_count() {
        // WinFsp asserts 64 entries. Each is a pointer, so the size is 64 pointers.
        assert_eq!(size_of::<Interface>(), 64 * size_of::<usize>());
    }
}
