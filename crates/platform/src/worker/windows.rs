use super::{CleanupFault, WORKER_CONTROL_ENV, WORKER_INPUTS_ENV, WorkerChannels, WorkerCommand};
#[cfg(feature = "native-test-hooks")]
use crate::native_test_hooks::{self as hooks, Action, Stage};
use crate::{PlatformError, ProcessIdentity};
use std::fs::File;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::sync::Mutex;
use std::time::Instant;
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::System::{JobObjects::*, Pipes::CreatePipe, Threading::*};

/// Serializes the window in which this module's child pipe ends are
/// inheritable. The explicit handle list limits what this launch passes; it
/// cannot stop an unrelated `bInheritHandles` spawn elsewhere in the process
/// from inheriting them, so the engine must not spawn such processes.
static INHERITABLE_WINDOW: Mutex<()> = Mutex::new(());

/// One anonymous pipe: `(parent end, child end)`. Both start non-inheritable.
fn pipe(child_reads: bool) -> Result<(OwnedHandle, OwnedHandle), PlatformError> {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: CreatePipe writes two new handles on success; null attributes
    // make them non-inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 65_536) } == 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: successful CreatePipe transfers both unique handles to us.
    let (read, write) = unsafe {
        (
            OwnedHandle::from_raw_handle(read.cast()),
            OwnedHandle::from_raw_handle(write.cast()),
        )
    };
    Ok(if child_reads {
        (write, read)
    } else {
        (read, write)
    })
}

/// A new read-only handle to `file` (ReOpenFile with read access only), and
/// its value, which the child sees unchanged after inheritance. The share
/// mode admits other readers only: a file still open for writing is refused,
/// and no writer can open it while the worker holds this handle.
pub(super) fn read_only_view(file: &File, _index: usize) -> Result<(File, u64), PlatformError> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_READ, FILE_TYPE_DISK, GetFileType, ReOpenFile,
    };
    let original: HANDLE = file.as_raw_handle().cast();
    // SAFETY: queries a live handle borrowed from `file`.
    if unsafe { GetFileType(original) } != FILE_TYPE_DISK || !super::is_regular_file(original) {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: ReOpenFile returns a new non-inheritable handle or INVALID_HANDLE_VALUE.
    let reopened = unsafe { ReOpenFile(original, GENERIC_READ, FILE_SHARE_READ, 0) };
    if reopened == INVALID_HANDLE_VALUE || reopened.is_null() {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: a successful ReOpenFile transfers a unique handle.
    let view = File::from(unsafe { OwnedHandle::from_raw_handle(reopened.cast()) });
    Ok((view, reopened as usize as u64))
}

pub(super) struct Worker {
    job: OwnedHandle,
    /// The direct worker's own process handle, pinned from creation.
    process: OwnedHandle,
}

/// Upper bound on job members tracked during termination; more fails closed.
const MAX_MEMBERS: usize = 4_096;

impl Worker {
    pub(super) fn launch(
        command: WorkerCommand,
    ) -> Result<
        (
            Self,
            ProcessIdentity,
            Option<ProcessIdentity>,
            WorkerChannels,
        ),
        PlatformError,
    > {
        // Unnamed and non-inheritable: only this owner keeps the kill-on-close job alive.
        let descriptor = crate::windows::private_descriptor()?;
        let security = crate::windows::private_security_attributes(&descriptor);
        let raw = unsafe { CreateJobObjectW(&security, std::ptr::null()) };
        if raw.is_null() {
            return Err(PlatformError::Io);
        }
        let job = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(PlatformError::Io);
        }

        let (to_worker, worker_commands) = pipe(true)?;
        let (from_worker, worker_reports) = pipe(false)?;
        let (diagnostics, worker_diagnostics) = pipe(false)?;
        let inputs = command.inputs;
        let mut inherited: Vec<HANDLE> = vec![
            worker_commands.as_raw_handle().cast(),
            worker_reports.as_raw_handle().cast(),
            worker_diagnostics.as_raw_handle().cast(),
        ];
        inherited.extend(
            inputs
                .iter()
                .map(|input| input.as_raw_handle().cast::<std::ffi::c_void>()),
        );

        let mut size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
        }
        if size == 0 {
            return Err(PlatformError::LaunchRestricted);
        }
        // The opaque list requires pointer alignment, not Vec<u8> alignment.
        let mut memory = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let attributes = memory.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &mut size) } == 0 {
            return Err(PlatformError::LaunchRestricted);
        }
        struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for Attributes {
            fn drop(&mut self) {
                unsafe {
                    DeleteProcThreadAttributeList(self.0);
                }
            }
        }
        let attributes = Attributes(attributes);
        #[cfg(feature = "native-test-hooks")]
        let bad_attribute =
            hooks::hit(Stage::WindowsAttributes, None, None)? == Action::FailAttribute;
        #[cfg(not(feature = "native-test-hooks"))]
        let bad_attribute = false;
        #[cfg(feature = "native-test-hooks")]
        let bad_assignment =
            hooks::hit(Stage::WindowsJobList, None, None)? == Action::FailAssignment;
        #[cfg(feature = "native-test-hooks")]
        let assignment_copy = if bad_assignment {
            use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
            let mut duplicate = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    raw,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(PlatformError::Io);
            }
            Some(unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) })
        } else {
            None
        };
        #[cfg(feature = "native-test-hooks")]
        let job_handle = assignment_copy
            .as_ref()
            .map_or(raw, |handle| handle.as_raw_handle().cast());
        #[cfg(not(feature = "native-test-hooks"))]
        let job_handle = raw;
        let jobs = [job_handle];
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.0,
                0,
                if bad_attribute {
                    usize::MAX
                } else {
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize
                },
                jobs.as_ptr().cast(),
                std::mem::size_of_val(&jobs),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            #[cfg(feature = "native-test-hooks")]
            hooks::native_failure(Stage::WindowsAttributeRejected, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
            return Err(PlatformError::LaunchRestricted);
        }
        // Deliberately invalidate only the test copy after attribute acceptance;
        // the real private job stays owned throughout the native CreateProcess.
        #[cfg(feature = "native-test-hooks")]
        drop(assignment_copy);
        // Exactly the three pipe ends and the listed read-only inputs are
        // inherited (WC-001, WE-004).
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.0,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_ptr().cast(),
                std::mem::size_of_val(inherited.as_slice()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(PlatformError::LaunchRestricted);
        }

        let application: Vec<u16> = command
            .executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut arguments = crate::windows::quote_argument(command.executable.as_os_str())?;
        for argument in &command.args {
            arguments.push(b' ' as u16);
            arguments.extend(crate::windows::quote_argument(argument)?);
        }
        arguments.push(0);
        let mut environment = Vec::new();
        let mut entries = command.environment;
        // Inherited handle values are identical in the child.
        entries.push((
            WORKER_CONTROL_ENV.into(),
            format!("{}:{}", inherited[0] as usize, inherited[1] as usize).into(),
        ));
        let names = inherited[3..]
            .iter()
            .map(|handle| (*handle as usize).to_string())
            .collect::<Vec<_>>()
            .join(",");
        entries.push((WORKER_INPUTS_ENV.into(), names.into()));
        entries.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
        for (key, value) in entries {
            environment.extend(key.encode_wide());
            environment.push(b'=' as u16);
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        if environment.len() == 1 {
            environment.push(0);
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
        startup.lpAttributeList = attributes.0;
        // No stdin; stdout and stderr go only to the diagnostics pipe.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = std::ptr::null_mut();
        startup.StartupInfo.hStdOutput = inherited[2];
        startup.StartupInfo.hStdError = inherited[2];
        let mut process = PROCESS_INFORMATION::default();
        #[cfg(feature = "native-test-hooks")]
        hooks::hit(Stage::WindowsCreate, None, None)?;
        let window = INHERITABLE_WINDOW.lock().map_err(|_| PlatformError::Io)?;
        for &handle in &inherited {
            // SAFETY: each value is a live pipe end or input view owned above.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                == 0
            {
                return Err(PlatformError::Io);
            }
        }
        // Inheritance is limited to the explicit handle list above. Atomic
        // job-list assignment precedes any user instruction; suspended launch
        // is an additional ownership gate.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                arguments.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup.StartupInfo,
                &mut process,
            )
        };
        // The child (if any) holds its copies; ours close now, ending the window.
        drop((worker_commands, worker_reports, worker_diagnostics, inputs));
        drop(window);
        if created == 0 {
            #[cfg(feature = "native-test-hooks")]
            hooks::native_failure(Stage::WindowsCreateRejected, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
            return Err(PlatformError::LaunchRestricted);
        }
        let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess.cast()) };
        let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread.cast()) };
        let worker = Self {
            job,
            process: process_handle,
        };
        let identity = ProcessIdentity {
            pid: process.dwProcessId,
            start_marker: crate::windows::process_start_marker(process.dwProcessId)?,
        };
        #[cfg(feature = "native-test-hooks")]
        hooks::hit(Stage::WindowsCreated, Some(identity.clone()), None)?;
        #[cfg(feature = "native-test-hooks")]
        let bad_resume =
            hooks::hit(Stage::WindowsResume, Some(identity.clone()), None)? == Action::FailResume;
        #[cfg(not(feature = "native-test-hooks"))]
        let bad_resume = false;
        let resume_handle = if bad_resume {
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
        } else {
            thread.as_raw_handle().cast()
        };
        if unsafe { ResumeThread(resume_handle) } == u32::MAX {
            #[cfg(feature = "native-test-hooks")]
            hooks::native_failure(Stage::WindowsResumeRejected, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
            return Err(PlatformError::Io);
        }
        let channels = WorkerChannels {
            to_worker: File::from(to_worker),
            from_worker: File::from(from_worker),
            diagnostics: File::from(diagnostics),
        };
        Ok((worker, identity, None, channels))
    }

    /// Whole-tree termination. `ActiveProcesses == 0` alone can be observed
    /// while a terminated member's process object is still exiting, so
    /// confirmation also requires every member handle held here to be
    /// signaled. Members are captured before termination and re-enumerated
    /// while any remain associated.
    pub(super) fn terminate(&mut self, deadline: Instant) -> Result<(), CleanupFault> {
        let job: HANDLE = self.job.as_raw_handle().cast();
        // Freeze membership first: with an active-process limit of 1 no new
        // process can join (existing members are unaffected), so the
        // snapshot below holds every member that termination will kill.
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(CleanupFault::NativeFailure);
        }
        let mut members: Vec<(u32, OwnedHandle)> = Vec::new();
        self.track_members(&mut members)?;
        if unsafe { TerminateJobObject(job, 1) } == 0 {
            return Err(CleanupFault::NativeFailure);
        }
        loop {
            let active = self.active_processes()?;
            if active > 0 {
                self.track_members(&mut members)?;
            }
            let exited = |handle: &OwnedHandle| {
                // SAFETY: a zero-timeout wait on a live owned handle.
                let state = unsafe { WaitForSingleObject(handle.as_raw_handle().cast(), 0) };
                state == windows_sys::Win32::Foundation::WAIT_OBJECT_0
            };
            if active == 0
                && exited(&self.process)
                && members.iter().all(|(_, handle)| exited(handle))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(CleanupFault::Deadline);
            }
            std::thread::sleep(
                std::time::Duration::from_millis(5)
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn active_processes(&self) -> Result<u32, CleanupFault> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw_handle().cast(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(CleanupFault::OwnershipLost);
        }
        Ok(info.ActiveProcesses)
    }

    /// Hold a SYNCHRONIZE handle for every process currently in the job.
    /// A PID that is no longer this job's member is not held: a reused PID
    /// can never stand in for a member, and an already-exited one needs none.
    fn track_members(&self, members: &mut Vec<(u32, OwnedHandle)>) -> Result<(), CleanupFault> {
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        const HEADER: usize = 2;
        let mut buffer = vec![0usize; HEADER + 256];
        let ids = loop {
            if unsafe {
                QueryInformationJobObject(
                    self.job.as_raw_handle().cast(),
                    JobObjectBasicProcessIdList,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * std::mem::size_of::<usize>()) as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                // A partial list is retried larger; anything else is a fault.
                if unsafe { windows_sys::Win32::Foundation::GetLastError() }
                    != windows_sys::Win32::Foundation::ERROR_MORE_DATA
                    || buffer.len() >= HEADER + MAX_MEMBERS
                {
                    return Err(CleanupFault::NativeFailure);
                }
                buffer = vec![0usize; HEADER + MAX_MEMBERS];
                continue;
            }
            // SAFETY: the buffer is pointer-aligned and the call filled a
            // JOBOBJECT_BASIC_PROCESS_ID_LIST header followed by its IDs.
            let header = unsafe { &*(buffer.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
            let listed = header.NumberOfProcessIdsInList as usize;
            if listed > buffer.len() - HEADER {
                return Err(CleanupFault::NativeFailure);
            }
            if (header.NumberOfAssignedProcesses as usize) > listed {
                if buffer.len() >= HEADER + MAX_MEMBERS {
                    return Err(CleanupFault::NativeFailure);
                }
                buffer = vec![0usize; HEADER + MAX_MEMBERS];
                continue;
            }
            // ProcessIdList begins after the two u32 counts (one usize).
            break buffer[1..1 + listed].to_vec();
        };
        for id in ids {
            let Ok(pid) = u32::try_from(id) else {
                return Err(CleanupFault::NativeFailure);
            };
            if members.iter().any(|(known, _)| *known == pid) {
                continue;
            }
            // SAFETY: OpenProcess returns a new handle or null.
            let raw =
                unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if raw.is_null() {
                // Only a vanished PID (exited and released) needs no wait; a
                // member that denies SYNCHRONIZE cannot be confirmed.
                if unsafe { windows_sys::Win32::Foundation::GetLastError() }
                    == windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER
                {
                    continue;
                }
                return Err(CleanupFault::NativeFailure);
            }
            // SAFETY: a successful OpenProcess transfers a unique handle.
            let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
            let mut in_job = 0;
            if unsafe {
                IsProcessInJob(
                    handle.as_raw_handle().cast(),
                    self.job.as_raw_handle().cast(),
                    &mut in_job,
                )
            } == 0
            {
                return Err(CleanupFault::NativeFailure);
            }
            if in_job != 0 {
                if members.len() >= MAX_MEMBERS {
                    return Err(CleanupFault::NativeFailure);
                }
                members.push((pid, handle));
            }
        }
        Ok(())
    }
}
