//! Windows root, ACL, file and owner operations.
//!
//! Keep Win32 calls here so the public platform API remains the same across
//! targets. Roots are created with a protected DACL for the current user, and
//! opened with `OPEN_REPARSE_POINT` before their type and ACL are inspected.

use crate::{OwnedRoot, OwnerIdentity, PlatformError, RelativePath, SafeFileMetadata};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INVALID_PARAMETER, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    GetAce, GetAclInformation, GetSecurityDescriptorControl, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, DeleteFileW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetVolumeInformationW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::core::PWSTR;

const MAX_TOKEN_INFO_BYTES: u32 = 64 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: Win32 allocated this descriptor with LocalAlloc-compatible
        // ownership through the security descriptor conversion API.
        unsafe { LocalFree(self.0.cast()) };
    }
}

pub(crate) fn current_owner_identity() -> Result<OwnerIdentity, PlatformError> {
    let sid = current_sid()?;
    Ok(OwnerIdentity::WindowsSid(sid))
}

pub(crate) fn process_owner_identity(pid: u32) -> Result<OwnerIdentity, PlatformError> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(PlatformError::Io);
    }
    // SAFETY: OpenProcess returned an owned process handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process.cast()) };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is live and `token` is a writable output slot.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: OpenProcessToken returned a new kernel handle owned by this call.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut required = 0_u32;
    // SAFETY: a null buffer with size zero is the documented size query.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 || required > MAX_TOKEN_INFO_BYTES {
        return Err(PlatformError::Io);
    }
    let words = required.div_ceil(std::mem::size_of::<u64>() as u32) as usize;
    let mut storage = vec![0_u64; words];
    let mut returned = 0_u32;
    // SAFETY: storage has the queried size and required alignment for TOKEN_USER.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            (storage.len() * std::mem::size_of::<u64>()) as u32,
            &mut returned,
        )
    } == 0
        || returned > (storage.len() * std::mem::size_of::<u64>()) as u32
    {
        return Err(PlatformError::Io);
    }
    // SAFETY: successful TokenUser output is a TOKEN_USER structure in storage.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if user.User.Sid.is_null() {
        return Err(PlatformError::Io);
    }
    // SAFETY: the SID pointer belongs to the still-live TokenUser buffer.
    let length = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) };
    if length == 0 || length > MAX_TOKEN_INFO_BYTES {
        return Err(PlatformError::Io);
    }
    // SAFETY: GetLengthSid returned the readable SID extent.
    let sid = unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length as usize) };
    Ok(OwnerIdentity::WindowsSid(sid.to_vec()))
}

pub(crate) fn process_start_marker(pid: u32) -> Result<String, PlatformError> {
    use windows_sys::Win32::Foundation::FILETIME;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(process_query_error());
    }
    // SAFETY: OpenProcess returned an owned process handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process.cast()) };
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: process is live and each FILETIME pointer is a writable output.
    if unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(process_query_error());
    }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    Ok(format!("windows-start-{ticks:016x}"))
}

pub(crate) fn process_query_error() -> PlatformError {
    if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
        PlatformError::NotFound
    } else {
        PlatformError::Io
    }
}

fn current_sid() -> Result<Vec<u8>, PlatformError> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is valid and `token` is a
    // writable output slot. The returned handle is immediately owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: OpenProcessToken returned a new kernel handle owned by this call.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut required = 0_u32;
    // SAFETY: a null buffer with size zero is the documented size query.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 || required > MAX_TOKEN_INFO_BYTES {
        return Err(PlatformError::Io);
    }

    // u64 storage gives the native TOKEN_USER structure its required alignment.
    let words = required.div_ceil(std::mem::size_of::<u64>() as u32) as usize;
    let mut storage = vec![0_u64; words];
    let mut returned = 0_u32;
    // SAFETY: `storage` is aligned, large enough for the queried structure, and
    // remains alive while the SID pointer is validated and copied.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            (storage.len() * std::mem::size_of::<u64>()) as u32,
            &mut returned,
        )
    } == 0
        || returned > (storage.len() * std::mem::size_of::<u64>()) as u32
    {
        return Err(PlatformError::Io);
    }
    // SAFETY: successful TokenUser output is a TOKEN_USER structure in storage.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if user.User.Sid.is_null() {
        return Err(PlatformError::Io);
    }
    // SAFETY: the SID pointer belongs to the still-live TokenUser buffer.
    let length = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) };
    if length == 0 || length > MAX_TOKEN_INFO_BYTES {
        return Err(PlatformError::Io);
    }
    // SAFETY: GetLengthSid returned the readable extent of this SID.
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length as usize) }.to_vec())
}

fn current_sid_string() -> Result<Vec<u16>, PlatformError> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let sid = current_sid()?;
    let mut string: PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` contains a validated SID copied from the current token and
    // `string` is an output slot for a LocalAlloc-owned UTF-16 string.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut string) } == 0 {
        return Err(PlatformError::Io);
    }
    let descriptor = LocalDescriptor(string.cast());
    let mut length = 0_usize;
    // SAFETY: the returned string is NUL-terminated and owned by descriptor.
    while unsafe { *string.add(length) } != 0 {
        length += 1;
        if length > 256 {
            return Err(PlatformError::Io);
        }
    }
    // SAFETY: the validated length is within the allocated SID string.
    let value = unsafe { std::slice::from_raw_parts(string, length) }.to_vec();
    drop(descriptor);
    Ok(value)
}

pub(crate) fn private_descriptor() -> Result<LocalDescriptor, PlatformError> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

    let sid = current_sid_string()?;
    let mut sddl: Vec<u16> = "D:P(A;OICI;FA;;;".encode_utf16().collect();
    sddl.extend(sid);
    sddl.push(b')' as u16);
    sddl.push(0);
    let mut descriptor = std::ptr::null_mut();
    let mut size = 0_u32;
    // SAFETY: `sddl` is NUL-terminated and both output pointers are writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            &mut size,
        )
    } == 0
        || descriptor.is_null()
        || size == 0
    {
        return Err(PlatformError::Io);
    }
    Ok(LocalDescriptor(descriptor))
}

pub(crate) fn private_security_attributes(
    descriptor: &LocalDescriptor,
) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
    windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

pub(crate) fn open_directory_chain(path: &Path, create: bool) -> Result<Vec<File>, PlatformError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || !matches!(path.components().next(), Some(Component::Prefix(_)))
    {
        return Err(PlatformError::InvalidPath);
    }

    let mut current = PathBuf::new();
    let mut directories = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                let directory = open_directory(&current, create)?;
                directories.push(directory);
            }
            Component::CurDir | Component::ParentDir => return Err(PlatformError::InvalidPath),
        }
    }
    if directories.is_empty() {
        Err(PlatformError::UnsafeRoot)
    } else {
        Ok(directories)
    }
}

pub(crate) fn ensure_private_directory(
    root: &OwnedRoot,
    path: &RelativePath,
) -> Result<(), PlatformError> {
    let mut current = root.path().to_path_buf();
    for component in path.components() {
        current.push(component);
        let directory = open_directory(&current, true)?;
        validate_directory(&directory, true)?;
    }
    Ok(())
}

fn open_directory(path: &Path, create: bool) -> Result<File, PlatformError> {
    if create {
        let descriptor = private_descriptor()?;
        let attributes = private_security_attributes(&descriptor);
        let encoded = wide_path(path);
        // SAFETY: the encoded path and security descriptor remain alive for the call.
        if unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) } == 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32)
            {
                return Err(map_io(error));
            }
        }
    }

    let encoded = wide_path(path);
    // SAFETY: CreateFileW receives a valid NUL-terminated path; the returned
    // handle is checked before ownership is transferred to `File`.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES | windows_sys::Win32::Storage::FileSystem::READ_CONTROL,
            // Keeping DELETE sharing disabled prevents other processes from
            // renaming a checked directory while its handle is retained.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let file = file_from_handle(handle)?;
    validate_directory_type(&file)?;
    Ok(file)
}

fn file_from_handle(handle: HANDLE) -> Result<File, PlatformError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    // SAFETY: the successful CreateFileW result is a unique owned kernel handle.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

pub(crate) fn validate_directory(
    file: &File,
    require_protected_dacl: bool,
) -> Result<(), PlatformError> {
    validate_directory_type(file)?;
    validate_acl(file, require_protected_dacl)
}

fn validate_directory_type(file: &File) -> Result<(), PlatformError> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the handle is live and the output buffer matches FileAttributeTagInfo.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(PlatformError::Io);
    }
    if information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(())
}

fn validate_file(file: &File) -> Result<(), PlatformError> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the handle is live and the output buffer matches the requested info class.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(PlatformError::Io);
    }
    if information.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(PlatformError::InvalidFile);
    }
    let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `file_info` is a writable output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut file_info) } == 0 {
        return Err(PlatformError::Io);
    }
    if file_info.nNumberOfLinks != 1 {
        return Err(PlatformError::InvalidFile);
    }
    validate_acl(file, false).map_err(|_| PlatformError::InvalidFile)
}

fn validate_acl(file: &File, require_protected_dacl: bool) -> Result<(), PlatformError> {
    let mut owner = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let requested: OBJECT_SECURITY_INFORMATION =
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: GetSecurityInfo reads the security descriptor for this open handle
    // and writes the returned pointers, all owned by the LocalFree descriptor.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            requested,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        if !descriptor.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor for LocalFree.
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(PlatformError::UnsafeRoot);
    }
    let descriptor = LocalDescriptor(descriptor);
    let current = current_sid()?;
    // SAFETY: both SIDs are valid and remain alive for the comparison.
    if unsafe { EqualSid(owner, current.as_ptr().cast_mut().cast()) } == 0 {
        return Err(PlatformError::UnsafeRoot);
    }
    if require_protected_dacl {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: the descriptor came from GetSecurityInfo and both outputs are writable.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(PlatformError::UnsafeRoot);
        }
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is owned by descriptor and info has the requested structure layout.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || info.AceCount == 0
    {
        return Err(PlatformError::UnsafeRoot);
    }
    let mut owner_has_full_access = false;
    for index in 0..info.AceCount {
        let mut ace_pointer: *mut c_void = std::ptr::null_mut();
        // SAFETY: index is bounded by the ACL's reported ACE count.
        if unsafe { GetAce(dacl, index, &mut ace_pointer) } == 0 || ace_pointer.is_null() {
            return Err(PlatformError::UnsafeRoot);
        }
        // SAFETY: GetAce returns an ACE_HEADER-compatible pointer inside dacl.
        let header = unsafe { &*ace_pointer.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(PlatformError::UnsafeRoot);
        }
        // SAFETY: the ACE type check establishes the ACCESS_ALLOWED_ACE layout.
        let ace = unsafe { &*ace_pointer.cast::<ACCESS_ALLOWED_ACE>() };
        // SAFETY: SidStart is the first aligned DWORD of the SID embedded in the ACE.
        let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        // SAFETY: EqualSid validates both pointers before comparing their SIDs.
        if unsafe { EqualSid(ace_sid, current.as_ptr().cast_mut().cast()) } == 0 {
            return Err(PlatformError::UnsafeRoot);
        }
        owner_has_full_access |= ace.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS;
    }
    if !owner_has_full_access {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(())
}

pub(crate) fn validate_filesystem(path: &Path) -> Result<(), PlatformError> {
    let prefix = path
        .components()
        .find_map(|part| match part {
            Component::Prefix(prefix) => Some(prefix.as_os_str()),
            _ => None,
        })
        .ok_or(PlatformError::InvalidPath)?;
    let mut volume_root = PathBuf::from(prefix);
    volume_root.push("\\");
    let encoded = wide_path(&volume_root);
    // SAFETY: the drive root is NUL-terminated and all output buffers are valid.
    if unsafe { GetDriveTypeW(encoded.as_ptr()) } != DRIVE_FIXED {
        return Err(PlatformError::UnsupportedRoot);
    }
    let mut filesystem = [0_u16; 32];
    // SAFETY: all buffers are correctly sized, writable and valid for the call.
    if unsafe {
        GetVolumeInformationW(
            encoded.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(PlatformError::Io);
    }
    let name = String::from_utf16_lossy(
        &filesystem[..filesystem
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(filesystem.len())],
    );
    if name.eq_ignore_ascii_case("NTFS") {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedRoot)
    }
}

pub(crate) fn file_metadata(
    root: &OwnedRoot,
    path: &RelativePath,
) -> Result<SafeFileMetadata, PlatformError> {
    let file = open_relative_file(root, path, false, false, false)?;
    validate_file(&file)?;
    let length = file.metadata().map_err(|_| PlatformError::Io)?.len();
    Ok(SafeFileMetadata { length })
}

pub(crate) fn remove_file(root: &OwnedRoot, path: &RelativePath) -> Result<(), PlatformError> {
    let _ = file_metadata(root, path)?;
    let wide = wide_path(&root.path().join(path.as_path()));
    // The final file was opened without following reparse points and checked
    // against the protected owner DACL immediately before this pathname call.
    // Same-user replacement races remain outside the approved threat model.
    if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn read_file(
    root: &OwnedRoot,
    path: &RelativePath,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    let mut file = open_relative_file(root, path, false, false, false)?;
    validate_file(&file)?;
    let maximum = maximum_bytes as u64;
    if file.metadata().map_err(|_| PlatformError::Io)?.len() > maximum {
        return Err(PlatformError::InvalidFile);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PlatformError::Io)?;
    if bytes.len() > maximum_bytes {
        return Err(PlatformError::InvalidFile);
    }
    Ok(bytes)
}

pub(crate) fn write_atomic(
    root: &OwnedRoot,
    path: &RelativePath,
    contents: &[u8],
) -> Result<(), PlatformError> {
    let (parent, name) = open_relative_parent(root, path, true)?;
    let destination = parent.join(&name);
    validate_replace_target(&destination)?;
    let mut staged = None;
    for _ in 0..64 {
        let temporary = parent.join(format!(
            ".d3d-tmp-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temporary)
        {
            Ok(file) => {
                staged = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    // Only clean up a staging file created by this invocation.
    let (temporary, mut file) = staged.ok_or(PlatformError::Busy)?;
    let result = (|| {
        file.write_all(contents).map_err(|_| PlatformError::Io)?;
        file.sync_all().map_err(|_| PlatformError::Io)?;
        validate_file(&file)?;
        drop(file);
        validate_replace_target(&destination)?;
        let from = wide_path(&temporary);
        let to = wide_path(&destination);
        // WRITE_THROUGH asks Windows to flush the move before returning; the
        // source file itself was flushed before it became visible at destination.
        // SAFETY: both paths are NUL-terminated and remain live for the call.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(map_io(std::io::Error::last_os_error()));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn open_lease_file(root: &OwnedRoot) -> Result<File, PlatformError> {
    let path = RelativePath::parse("authority.lock")?;
    open_relative_file(root, &path, true, true, false)
}

fn open_relative_file(
    root: &OwnedRoot,
    path: &RelativePath,
    create: bool,
    write: bool,
    create_new: bool,
) -> Result<File, PlatformError> {
    let (parent, name) = open_relative_parent(root, path, create)?;
    let target = parent.join(name);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if create_new {
        options.create_new(true);
    } else if create {
        options.create(true);
    }
    let file = options.open(target).map_err(map_io)?;
    validate_file(&file)?;
    Ok(file)
}

fn open_relative_parent(
    root: &OwnedRoot,
    path: &RelativePath,
    create: bool,
) -> Result<(PathBuf, String), PlatformError> {
    let components = path.components().collect::<Vec<_>>();
    let Some((name, directories)) = components.split_last() else {
        return Err(PlatformError::InvalidPath);
    };
    let mut parent = root.path().to_path_buf();
    for component in directories {
        parent.push(component);
        let directory = open_directory(parent.as_path(), create)?;
        validate_directory(&directory, false)?;
    }
    Ok((parent, (*name).to_owned()))
}

fn validate_replace_target(path: &Path) -> Result<(), PlatformError> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => validate_file(&file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_io(error)),
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn map_io(error: std::io::Error) -> PlatformError {
    match error.kind() {
        std::io::ErrorKind::NotFound => PlatformError::NotFound,
        std::io::ErrorKind::AlreadyExists => PlatformError::UnsafeRoot,
        _ => PlatformError::Io,
    }
}
