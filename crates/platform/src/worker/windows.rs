use super::{CleanupFault, WorkerCommand};
#[cfg(feature = "native-test-hooks")]
use crate::native_test_hooks::{self as hooks, Action, Stage};
use crate::{PlatformError, ProcessIdentity};
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::time::Instant;
use windows_sys::Win32::System::{JobObjects::*, Threading::*};

pub(super) struct Worker {
    job: OwnedHandle,
}

impl Worker {
    pub(super) fn launch(
        command: WorkerCommand,
    ) -> Result<(Self, ProcessIdentity, Option<ProcessIdentity>), PlatformError> {
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

        let mut size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            return Err(PlatformError::LaunchRestricted);
        }
        // The opaque list requires pointer alignment, not Vec<u8> alignment.
        let mut memory = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let attributes = memory.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) } == 0 {
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
        let mut process = PROCESS_INFORMATION::default();
        #[cfg(feature = "native-test-hooks")]
        hooks::hit(Stage::WindowsCreate, None, None)?;
        // Empty inherited-handle set (FALSE). Atomic job-list assignment precedes
        // any user instruction; suspended launch is an additional ownership gate.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                arguments.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup.StartupInfo,
                &mut process,
            )
        } == 0
        {
            #[cfg(feature = "native-test-hooks")]
            hooks::native_failure(Stage::WindowsCreateRejected, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
            return Err(PlatformError::LaunchRestricted);
        }
        let _process = unsafe { OwnedHandle::from_raw_handle(process.hProcess.cast()) };
        let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread.cast()) };
        let worker = Self { job };
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
        Ok((worker, identity, None))
    }

    pub(super) fn terminate(&mut self, deadline: Instant) -> Result<(), CleanupFault> {
        let job = self.job.as_raw_handle().cast();
        if unsafe { TerminateJobObject(job, 1) } == 0 {
            return Err(CleanupFault::NativeFailure);
        }
        loop {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(CleanupFault::OwnershipLost);
            }
            if info.ActiveProcesses == 0 {
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
}
