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
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, GetDiskFreeSpaceExW, GetDriveTypeW,
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

pub(crate) fn quote_argument(value: &std::ffi::OsStr) -> Result<Vec<u16>, PlatformError> {
    let mut result = vec![u16::from(b'"')];
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(PlatformError::InvalidPath);
        }
        if unit == u16::from(b'\\') {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(u16::from(b'\\'), slashes));
        if unit == u16::from(b'"') {
            result.extend(std::iter::repeat_n(u16::from(b'\\'), slashes + 1));
        }
        slashes = 0;
        result.push(unit);
    }
    result.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
    result.push(u16::from(b'"'));
    Ok(result)
}

/// Launch without inheriting any launcher handles, including captured output.
pub(crate) fn spawn_detached_engine(
    command: &std::process::Command,
) -> Result<(OwnedHandle, u32), PlatformError> {
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
        CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let application = command
        .get_program()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut arguments = quote_argument(command.get_program())?;
    for argument in command.get_args() {
        arguments.push(u16::from(b' '));
        arguments.extend(quote_argument(argument)?);
    }
    arguments.push(0);
    let mut environment = Vec::new();
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            environment.extend(key.encode_wide());
            environment.push(u16::from(b'='));
            environment.extend(value.encode_wide());
            environment.push(0);
        }
    }
    environment.push(0);
    if environment.len() == 1 {
        environment.push(0);
    }
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: all input buffers are NUL-terminated and live through the call;
    // outputs are writable. FALSE forbids inheritance of every parent handle.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            arguments.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            DETACHED_PROCESS
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_BREAKAWAY_FROM_JOB
                | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            std::ptr::null(),
            &startup,
            &mut process,
        )
    } == 0
    {
        return Err(
            if std::io::Error::last_os_error().raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
            {
                PlatformError::LaunchRestricted
            } else {
                PlatformError::Io
            },
        );
    }
    // SAFETY: successful CreateProcessW transfers both unique handles to us.
    let child = unsafe { OwnedHandle::from_raw_handle(process.hProcess.cast()) };
    // SAFETY: the primary thread handle is separately owned and can close now.
    drop(unsafe { OwnedHandle::from_raw_handle(process.hThread.cast()) });
    Ok((child, process.dwProcessId))
}

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
    // Only a directory created by this call is engine-owned; every
    // pre-existing ancestor above the root is external (DS-G04 step 4).
    let mut parent_owned = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                let (directory, created) = open_directory(&current, create, parent_owned)?;
                parent_owned = created;
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
        let (directory, _) = open_directory(&current, true, true)?;
        validate_directory(&directory, true)?;
    }
    Ok(())
}

/// Open one directory without following reparse points, creating it when
/// asked. Returns whether this call created it.
///
/// A newly created directory and its parent are flushed before the chain
/// continues. An engine-owned parent must flush; an external pre-existing
/// parent is flushed only when this user can open it for writing.
fn open_directory(
    path: &Path,
    create: bool,
    parent_owned: bool,
) -> Result<(File, bool), PlatformError> {
    let mut created = false;
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
        } else {
            created = true;
            // Do not continue down a newly created chain after a failed barrier.
            drop(flush_owned_directory(path)?);
            let parent = path.parent().ok_or(PlatformError::InvalidPath)?;
            if parent_owned {
                drop(flush_owned_directory(parent)?);
            } else {
                flush_external_parent_if_writable(parent)?;
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
            // DELETE sharing is withheld, but these attribute/READ_CONTROL-only
            // opens do not take part in share-access checks, so they do NOT
            // stop a rename (observed 2026-11-23). Durable mutations rely on
            // the root identity recheck (verify_root_identity) instead.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let file = file_from_handle(handle)?;
    validate_directory_type(&file)?;
    Ok((file, created))
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
    if !supported_filesystem_name(&filesystem) {
        return Err(PlatformError::UnsupportedRoot);
    }
    refuse_cloud_sync_root(path)
}

/// DS-G04 step 5: only local fixed NTFS is a supported durable root. ReFS,
/// FAT, exFAT and every other reported name are refused.
fn supported_filesystem_name(name: &[u16]) -> bool {
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("NTFS")
}

/// Recheck the filesystem through an open handle, so a volume reached by a
/// path the drive-letter check did not see is still refused.
fn validate_volume_by_handle(file: &File) -> Result<(), PlatformError> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    let mut filesystem = [0_u16; 32];
    // SAFETY: the handle is live and every buffer is writable for its stated size.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
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
    if supported_filesystem_name(&filesystem) {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedRoot)
    }
}

/// Refuse any root inside a registered Cloud Files sync root (OneDrive, Box
/// and other providers), whatever its folder name. The nearest existing
/// ancestor is queried so a root can be refused before it is created.
fn refuse_cloud_sync_root(path: &Path) -> Result<(), PlatformError> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_SYNC_ROOT_INFO_BASIC, CfGetSyncRootInfoByPath,
    };
    let existing = path
        .ancestors()
        .find(|ancestor| fs::symlink_metadata(ancestor).is_ok())
        .ok_or(PlatformError::InvalidPath)?;
    let encoded = wide_path(existing);
    let mut information = [0_u64; 64];
    let mut returned = 0_u32;
    // SAFETY: the path is NUL-terminated; the aligned buffer is writable for
    // its full byte length and `returned` is a writable output.
    let status = unsafe {
        CfGetSyncRootInfoByPath(
            encoded.as_ptr(),
            CF_SYNC_ROOT_INFO_BASIC,
            information.as_mut_ptr().cast(),
            std::mem::size_of_val(&information) as u32,
            &mut returned,
        )
    };
    classify_sync_root_status(status)
}

/// The only `CfGetSyncRootInfoByPath` failures that mean "not a sync root",
/// as recorded in the DS-G04 decision (observed 2026-11-23):
/// ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT for an ordinary folder and
/// ERROR_INVALID_FUNCTION on a volume with no cloud filter attached.
const NOT_A_SYNC_ROOT: [u32; 2] = [
    windows_sys::Win32::Foundation::ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT,
    windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION,
];

/// Success means "inside a sync root". Only the recorded Win32 codes mean
/// "not a sync root"; any other failure is refused rather than assumed safe.
fn classify_sync_root_status(status: i32) -> Result<(), PlatformError> {
    const FACILITY_WIN32: u32 = 0x8007_0000;
    let code = status as u32;
    if code & 0xFFFF_0000 == FACILITY_WIN32 && NOT_A_SYNC_ROOT.contains(&(code & 0xFFFF)) {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedRoot)
    }
}

pub(crate) fn available_space_bytes(root: &OwnedRoot) -> Result<u64, PlatformError> {
    let path = wide_path(root.path());
    let mut available = 0_u64;
    // SAFETY: `path` is a live NUL-terminated UTF-16 path and `available` is a
    // writable output. The other optional outputs are not needed.
    if unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(PlatformError::Io);
    }
    Ok(available)
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

// ---------------------------------------------------------------------------
// Namespace durability protocol (DS-G04 decision, 2026-11-23).
//
// 1. File data: FlushFileBuffers on the file before it becomes visible.
// 2. Publication: MoveFileExW(MOVEFILE_WRITE_THROUGH) without
//    MOVEFILE_REPLACE_EXISTING or MOVEFILE_COPY_ALLOWED: an existing name or a
//    cross-volume move fails. Recovery records are the documented exception:
//    they are atomic replace-updates on every target (see write_atomic).
// 3. Flush every engine-owned directory from the root to the target's parent
//    through write-access, BACKUP_SEMANTICS, OPEN_REPARSE_POINT handles.
// 4. Never flush a pre-existing ancestor above the root (standard users get
//    ERROR_ACCESS_DENIED at `C:\`). Instead re-verify the retained root's
//    identity (volume serial + file index) against a fresh no-follow open,
//    and flush the root's parent once, at creation, when it is writable.
// 5. Supported storage is local fixed NTFS outside cloud sync roots.
//
// These are process-crash and handle-reopen guarantees under the documented
// Win32 contracts. They are not physical power-loss evidence.
// ---------------------------------------------------------------------------

/// Record of every barrier, in order, kept only by test builds so barrier
/// order is mutation-sensitive. Normal builds construct and discard nothing.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Barrier {
    File(PathBuf),
    Directory(PathBuf),
    ExternalParent { path: PathBuf, flushed: bool },
    RootIdentity(PathBuf),
    Publish(PathBuf),
}

#[cfg(test)]
thread_local! {
    static BARRIERS: std::cell::RefCell<Vec<Barrier>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn take_barriers() -> Vec<Barrier> {
    BARRIERS.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

#[cfg(test)]
fn note(barrier: impl FnOnce() -> Barrier) {
    BARRIERS.with(|log| log.borrow_mut().push(barrier()));
}

#[cfg(not(test))]
fn note(_: impl FnOnce() -> Barrier) {}

/// Native identity of an open file or directory on one volume. NTFS keeps a
/// file index stable until deletion; ReFS (unsupported) needs 128-bit IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

pub(crate) fn file_identity(file: &File) -> Result<FileIdentity, PlatformError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `information` is a writable output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(PlatformError::Io);
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

/// Step 4: the retained root handle must still be the directory a fresh
/// no-follow open of the selected path reaches. A rename-and-replace of the
/// root or any ancestor after open fails this check. The fresh chain is
/// returned for callers that keep it open; it does not block renames.
///
/// A selected root that no longer exists is `UnsafeRoot`, never `NotFound`:
/// callers read `NotFound` as "this entry is absent" (for example to release
/// a storage charge), which a moved root must not imply.
pub(crate) fn verify_root_identity(root: &OwnedRoot) -> Result<Vec<File>, PlatformError> {
    verify_root_identity_against(root.path(), root.windows_root_handle()).map_err(root_missing)
}

fn root_missing(error: PlatformError) -> PlatformError {
    if error == PlatformError::NotFound {
        PlatformError::UnsafeRoot
    } else {
        error
    }
}

/// Path-based opens report a moved root the same way as an absent entry.
/// `NotFound` passes through only once the root is confirmed in place.
fn confirm_absent<T>(
    root: &OwnedRoot,
    result: Result<T, PlatformError>,
) -> Result<T, PlatformError> {
    if matches!(result, Err(PlatformError::NotFound)) {
        drop(verify_root_identity(root)?);
    }
    result
}

fn verify_root_identity_against(path: &Path, retained: &File) -> Result<Vec<File>, PlatformError> {
    crate::root::validate_storage_path(path)?;
    validate_filesystem(path)?;
    let fresh = open_directory_chain(path, false)?;
    let selected = fresh.last().ok_or(PlatformError::UnsafeRoot)?;
    validate_directory(selected, true)?;
    validate_volume_by_handle(selected)?;
    if file_identity(selected)? != file_identity(retained)? {
        return Err(PlatformError::UnsafeRoot);
    }
    note(|| Barrier::RootIdentity(path.to_path_buf()));
    Ok(fresh)
}

/// Root preflight shared by capability checks and every durable mutation:
/// verified identity, then a flush of the root directory itself.
pub(crate) fn durable_preflight(root: &OwnedRoot) -> Result<(), PlatformError> {
    let _held = verify_root_identity(root)?;
    let flushed = flush_owned_directory(root.path()).map_err(root_missing)?;
    if file_identity(&flushed)? != file_identity(root.windows_root_handle())? {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(())
}

/// Step 3 for one engine-owned directory: open it for writing without
/// following reparse points or sharing DELETE, check its private ACL and
/// flush it. The handle is returned so callers can keep it pinned.
fn flush_owned_directory(path: &Path) -> Result<File, PlatformError> {
    let directory = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(map_io)?;
    validate_directory(&directory, false)?;
    directory.sync_all().map_err(|_| PlatformError::Io)?;
    note(|| Barrier::Directory(path.to_path_buf()));
    Ok(directory)
}

/// Step 3 for a path: the root, then each engine-owned directory down to the
/// parent of `relative`. All handles stay open until every flush finishes.
fn flush_owned_chain(root: &OwnedRoot, relative: &RelativePath) -> Result<(), PlatformError> {
    let components = relative.components().collect::<Vec<_>>();
    let mut current = root.path().to_path_buf();
    let first = flush_owned_directory(&current)?;
    if file_identity(&first)? != file_identity(root.windows_root_handle())? {
        return Err(PlatformError::UnsafeRoot);
    }
    let mut held = vec![first];
    for component in &components[..components.len() - 1] {
        current.push(component);
        held.push(flush_owned_directory(&current)?);
    }
    Ok(())
}

/// Step 4 at creation: flush an external parent once, only when this user
/// may open it for writing. Access denial is the documented standard-user
/// outcome for protected ancestors such as `C:\`, not a failed barrier.
fn flush_external_parent_if_writable(path: &Path) -> Result<(), PlatformError> {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(directory) => {
            validate_directory_type(&directory)?;
            directory.sync_all().map_err(|_| PlatformError::Io)?;
            note(|| Barrier::ExternalParent {
                path: path.to_path_buf(),
                flushed: true,
            });
            Ok(())
        }
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            note(|| Barrier::ExternalParent {
                path: path.to_path_buf(),
                flushed: false,
            });
            Ok(())
        }
        Err(error) => Err(map_io(error)),
    }
}

fn flush_file(file: &File, path: &Path) -> Result<(), PlatformError> {
    file.sync_all().map_err(|_| PlatformError::Io)?;
    note(|| Barrier::File(path.to_path_buf()));
    Ok(())
}

pub(crate) fn begin_input(root: &OwnedRoot, path: &RelativePath) -> Result<File, PlatformError> {
    // Recheck the root's identity before authorizing content below it.
    durable_preflight(root)?;
    let (parent, name) = open_relative_parent(root, path, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent.join(name))
        .map_err(map_io)?;
    validate_file(&file)?;
    Ok(file)
}

pub(crate) fn open_input(root: &OwnedRoot, path: &RelativePath) -> Result<File, PlatformError> {
    open_relative_file(root, path, false, false, false)
}

pub(crate) fn finish_input(
    root: &OwnedRoot,
    file: File,
    staged: &RelativePath,
    final_name: &RelativePath,
    checkpoint: &mut impl FnMut(crate::input_files::PublicationStep) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    use crate::input_files::PublicationStep;
    validate_file(&file)?;
    let identity = file_identity(&file)?;
    let staged_path = root.path().join(staged.as_path());
    checkpoint(PublicationStep::DataSync)?;
    // Step 1: the bytes are on stable storage before the name can appear.
    flush_file(&file, &staged_path)?;
    let (from, staged_name) = open_relative_parent(root, staged, false)?;
    let (to, name) = open_relative_parent(root, final_name, true)?;
    let from_handles = open_directory_chain(&from, false)?;
    let to_handles = open_directory_chain(&to, false)?;
    // Keep every checked directory open until publication and its barriers
    // finish. These handles do not block renames; the final root identity
    // recheck is what binds the published name to the selected root.
    for directory in from_handles.iter().chain(&to_handles) {
        validate_directory_type(directory)?;
    }
    drop(file);
    let from = from.join(staged_name);
    let to = to.join(name);
    checkpoint(PublicationStep::Publish)?;
    publish_without_replacing(&from, &to)?;
    checkpoint(PublicationStep::NamespaceSync)?;
    let published = open_relative_file(root, final_name, false, true, false)?;
    if file_identity(&published)? != identity {
        return Err(PlatformError::InvalidFile);
    }
    flush_file(&published, &to)?;
    // Step 3: both affected directory chains, root first.
    flush_owned_chain(root, final_name)?;
    flush_owned_chain(root, staged)?;
    // Step 4: the published name is reachable from the selected root.
    drop(verify_root_identity(root)?);
    drop((from_handles, to_handles));
    checkpoint(PublicationStep::FinalSync)
}

/// Step 2. No REPLACE_EXISTING or COPY_ALLOWED: a collision or cross-volume
/// move fails instead of overwriting or copying.
fn publish_without_replacing(from: &Path, to: &Path) -> Result<(), PlatformError> {
    let source = wide_path(from);
    let destination = wide_path(to);
    // SAFETY: both checked, protected paths are NUL terminated and live.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    note(|| Barrier::Publish(to.to_path_buf()));
    Ok(())
}

/// Complete a recovery record already placed by `write_atomic` (which
/// flushed its data before the write-through rename): flush the final file,
/// every owned directory to its parent, then re-verify the root.
pub(crate) fn complete_recovery_record(
    root: &OwnedRoot,
    relative: &RelativePath,
) -> Result<(), PlatformError> {
    let file = open_relative_file(root, relative, false, true, false)?;
    flush_file(&file, &root.path().join(relative.as_path()))?;
    flush_owned_chain(root, relative)?;
    drop(verify_root_identity(root)?);
    Ok(())
}

pub(crate) fn remove_input_durable(
    root: &OwnedRoot,
    path: &RelativePath,
) -> Result<(), PlatformError> {
    durable_preflight(root)?;
    match confirm_absent(root, remove_file(root, path)) {
        Ok(()) | Err(PlatformError::NotFound) => {}
        Err(error) => return Err(error),
    }
    confirm_absent(root, flush_owned_chain(root, path))?;
    drop(verify_root_identity(root)?);
    Ok(())
}

/// Move one direct child of an engine directory into quarantine without
/// following, opening for data or deleting it. The entry is opened for
/// DELETE with OPEN_REPARSE_POINT and renamed by handle with
/// ReplaceIfExists = FALSE, so links and directories move as themselves.
/// Callers validate the feature/quarantine pairing and entry name first.
pub(crate) fn quarantine_owned_entry(
    root: &OwnedRoot,
    source_directory: &RelativePath,
    entry_name: &std::ffi::OsStr,
    destination: &RelativePath,
) -> Result<(), PlatformError> {
    // The engine reads NotFound as "already gone"; a moved root is not that.
    confirm_absent(
        root,
        quarantine_entry(root, source_directory, entry_name, destination),
    )
}

fn quarantine_entry(
    root: &OwnedRoot,
    source_directory: &RelativePath,
    entry_name: &std::ffi::OsStr,
    destination: &RelativePath,
) -> Result<(), PlatformError> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_RENAME_INFO, FILE_SHARE_DELETE, FileRenameInfo, SECURITY_IDENTIFICATION,
        SYNCHRONIZE, SetFileInformationByHandle,
    };
    durable_preflight(root)?;
    // A fixed placeholder child names the source folder's chain for flushing;
    // the untrusted entry name itself is never parsed as a relative path.
    let source_chain = RelativePath::parse(format!("{}/entry", source_directory.as_str()))?;
    let (source_parent, _) = open_relative_parent(root, &source_chain, false)?;
    let source_handles = open_directory_chain(&source_parent, false)?;
    let (destination_parent, destination_name) = open_relative_parent(root, destination, true)?;
    let destination_handles = open_directory_chain(&destination_parent, false)?;
    let target = verbatim(&destination_parent.join(&destination_name))?;
    match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&target)
    {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(PlatformError::Busy),
    }
    // Verbatim: a listed `CON` or `name.` is that file, not a device or an
    // alias produced by Win32 path normalization.
    let mut source = verbatim(&source_parent)?;
    source.push(entry_name);
    let entry = OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(&source)
        .map_err(map_io)?;
    let name = target.as_os_str().encode_wide().collect::<Vec<_>>();
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let bytes = header + (name.len() + 1) * 2;
    // u64 storage keeps the HANDLE-bearing structure aligned.
    let mut buffer = vec![0_u64; bytes.div_ceil(8)];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the buffer is aligned and large enough for the fixed header plus
    // the NUL-terminated name; every field is written before the call.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = std::ptr::null_mut();
        (*information).FileNameLength = (name.len() * 2) as u32;
        let target_name = buffer.as_mut_ptr().cast::<u8>().add(header).cast::<u16>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), target_name, name.len());
        *target_name.add(name.len()) = 0;
    }
    // SAFETY: `entry` is live with DELETE access and the buffer holds a
    // complete FILE_RENAME_INFO of `bytes` bytes.
    if unsafe {
        SetFileInformationByHandle(
            entry.as_raw_handle(),
            FileRenameInfo,
            buffer.as_ptr().cast(),
            bytes as u32,
        )
    } == 0
    {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    note(|| Barrier::Publish(target.clone()));
    drop(entry);
    flush_owned_chain(root, &source_chain)?;
    flush_owned_chain(root, destination)?;
    drop(verify_root_identity(root)?);
    drop((source_handles, destination_handles));
    Ok(())
}

pub(crate) fn open_lease_file_at(
    root: &OwnedRoot,
    path: &RelativePath,
) -> Result<File, PlatformError> {
    open_relative_file(root, path, true, true, false)
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
        let (directory, _) = open_directory(parent.as_path(), create, true)?;
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

/// Verbatim (`\\?\` prefixed) form of a checked drive-letter path, so the final names are
/// used exactly as listed. Other prefixes are refused.
fn verbatim(path: &Path) -> Result<PathBuf, PlatformError> {
    use std::path::Prefix;
    let mut result = std::ffi::OsString::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                    result.push(format!(r"\\?\{}:", char::from(letter)));
                }
                _ => return Err(PlatformError::InvalidPath),
            },
            Component::RootDir => {}
            Component::Normal(name) => {
                result.push("\\");
                result.push(name);
            }
            Component::CurDir | Component::ParentDir => return Err(PlatformError::InvalidPath),
        }
    }
    Ok(PathBuf::from(result))
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

/// Create a new private attempt folder and keep a listing handle on it.
///
/// The handle is opened without DELETE sharing, so the folder cannot be
/// renamed or removed while the engine holds it; `ERROR_ALREADY_EXISTS`
/// refuses reuse.
pub(crate) fn create_attempt_directory(
    root: &OwnedRoot,
    relative: &RelativePath,
) -> Result<File, PlatformError> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_LIST_DIRECTORY, READ_CONTROL, SYNCHRONIZE};
    let components = relative.components().collect::<Vec<_>>();
    if components.len() > 1 {
        let parent = RelativePath::parse(components[..components.len() - 1].join("/"))?;
        ensure_private_directory(root, &parent)?;
    }
    let path = root.path().join(relative.as_path());
    let descriptor = private_descriptor()?;
    let attributes = private_security_attributes(&descriptor);
    let encoded = wide_path(&path);
    // SAFETY: the encoded path and security descriptor remain alive for the call.
    if unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        return Err(
            if matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32)
            {
                PlatformError::Busy
            } else {
                map_io(error)
            },
        );
    }
    drop(flush_owned_directory(
        path.parent().ok_or(PlatformError::InvalidPath)?,
    )?);
    // SAFETY: CreateFileW receives a valid NUL-terminated path; the returned
    // handle is checked before ownership is transferred to `File`.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let directory = file_from_handle(handle)?;
    validate_directory(&directory, true)?;
    Ok(directory)
}

/// One entry of a retained attempt folder, as listed through its handle.
pub(crate) struct ListedEntry {
    /// The entry name when it is valid UTF-16 (else it can never be expected).
    pub(crate) name: Option<String>,
    /// Neither directory, reparse point nor device.
    pub(crate) regular: bool,
    pub(crate) volume_serial: u64,
    pub(crate) file_index: u64,
}

/// List a retained folder by handle. More than `max` entries is refused.
pub(crate) fn list_attempt_directory(
    directory: &File,
    max: usize,
) -> Result<Vec<ListedEntry>, PlatformError> {
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo,
        FileIdBothDirectoryRestartInfo,
    };
    let mut volume = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `volume` is a writable output structure.
    if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), &mut volume) } == 0 {
        return Err(PlatformError::Io);
    }
    let device = u64::from(volume.dwVolumeSerialNumber);
    // u64 storage keeps every 8-byte-aligned entry aligned.
    let mut buffer = vec![0_u64; 8_192];
    let size = buffer.len() * 8;
    let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut entries = Vec::new();
    let mut class = FileIdBothDirectoryRestartInfo;
    loop {
        // SAFETY: the handle is live and the buffer is writable for `size` bytes.
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                size as u32,
            )
        } == 0
        {
            // SAFETY: reads the calling thread's last-error value.
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                return Ok(entries);
            }
            return Err(PlatformError::Io);
        }
        class = FileIdBothDirectoryInfo;
        let base = buffer.as_ptr().cast::<u8>();
        let mut offset = 0_usize;
        loop {
            // The whole fixed struct is read below, not just up to FileName.
            if offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > size {
                return Err(PlatformError::Io);
            }
            // SAFETY: the fixed part lies inside the buffer (checked above).
            let info = unsafe {
                std::ptr::read_unaligned(base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let length = info.FileNameLength as usize;
            if !length.is_multiple_of(2) || offset + name_offset + length > size {
                return Err(PlatformError::Io);
            }
            let units = (0..length / 2)
                // SAFETY: each unit lies inside the buffer (checked above).
                .map(|i| unsafe {
                    std::ptr::read_unaligned(base.add(offset + name_offset + 2 * i).cast::<u16>())
                })
                .collect::<Vec<_>>();
            let dot = units == [b'.' as u16] || units == [b'.' as u16, b'.' as u16];
            if !dot {
                if entries.len() == max {
                    return Err(PlatformError::InvalidFile);
                }
                let regular = info.FileAttributes
                    & (FILE_ATTRIBUTE_DIRECTORY
                        | FILE_ATTRIBUTE_REPARSE_POINT
                        | FILE_ATTRIBUTE_DEVICE)
                    == 0;
                entries.push(ListedEntry {
                    name: String::from_utf16(&units).ok(),
                    regular,
                    volume_serial: device,
                    file_index: info.FileId as u64,
                });
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset += info.NextEntryOffset as usize;
        }
    }
}

/// Open one attempt file read-only without following reparse points, denying
/// writers and deleters while held. Returns (file, volume serial, file index,
/// length) after checking disk type, single link and private ownership.
pub(crate) fn open_attempt_file(path: &Path) -> Result<(File, u64, u64, u64), PlatformError> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_TYPE_DISK, GetFileType, SECURITY_IDENTIFICATION,
    };
    // SECURITY_IDENTIFICATION and the disk-type check: a planted pipe cannot
    // impersonate or stall (reference: codex exec-server regular_file.rs).
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(path)
        .map_err(map_io)?;
    // SAFETY: `file` owns this handle for the duration of the call.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(PlatformError::InvalidFile);
    }
    validate_file(&file)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `info` is a writable output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(PlatformError::Io);
    }
    Ok((
        file,
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    ))
}

#[cfg(test)]
#[path = "windows_durability_tests.rs"]
mod durability_tests;
