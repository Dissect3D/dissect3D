//! Private, bounded native enrollment channels.
//!
//! This module transports one length-prefixed JSON frame per connection. It
//! reports the OS peer identity but leaves schema decoding and enrollment
//! authorization to the engine. The channel is never exposed over TCP.

use crate::{OwnedRoot, OwnerIdentity, PlatformError, RelativePath, current_owner_identity};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[cfg(unix)]
fn unix_connect_until(
    path: &std::path::Path,
    deadline: Instant,
) -> Result<std::os::unix::net::UnixStream, PlatformError> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let path_bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is a plain native address record; zero initialization
    // also supplies the required terminator after the validated path bytes.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path_bytes.is_empty()
        || path_bytes.contains(&0)
        || path_bytes.len() >= address.sun_path.len()
    {
        return Err(PlatformError::InvalidPath);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *target = *source as libc::c_char;
    }
    let address_len = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(path_bytes.len() + 1)
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or(PlatformError::InvalidPath)?;
    // SAFETY: socket returns a new descriptor or -1. Ownership is immediately
    // transferred to OwnedFd so every error path closes it.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: descriptor was returned by socket and has not been adopted yet.
    let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: both fcntl calls operate on this live, owned socket descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(PlatformError::Io);
    }
    // SAFETY: address is initialized, address_len names its populated prefix,
    // and owned remains live for this call.
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS)
            && error.raw_os_error() != Some(libc::EAGAIN)
        {
            return Err(PlatformError::Io);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PlatformError::Busy);
        }
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll points to one valid pollfd; the deadline is converted
        // to a finite native timeout.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Err(PlatformError::Busy);
        }
        if ready < 0 {
            return Err(PlatformError::Io);
        }
        let mut socket_error: libc::c_int = 0;
        let mut option_len = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        // SAFETY: output pointers refer to initialized writable storage and the
        // descriptor remains owned and valid.
        let status = unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut option_len,
            )
        };
        if status != 0 || socket_error != 0 {
            return Err(PlatformError::Io);
        }
    }
    let stream = std::os::unix::net::UnixStream::from(owned);
    // Frame I/O uses poll against an absolute deadline, so the socket remains
    // nonblocking even when readiness races with a concurrent local peer.
    stream
        .set_nonblocking(true)
        .map_err(|_| PlatformError::Io)?;
    Ok(stream)
}

#[cfg(unix)]
fn unix_read_exact_until(
    stream: &mut std::os::unix::net::UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<(), PlatformError> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut offset = 0;
    while offset < buffer.len() {
        unix_wait_until(stream.as_raw_fd(), libc::POLLIN, deadline, cancellation)?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(PlatformError::Io);
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Err(PlatformError::Busy);
            }
            Err(_error) => {
                return Err(PlatformError::Io);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_wait_until(
    descriptor: std::os::fd::RawFd,
    event: libc::c_short,
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<(), PlatformError> {
    loop {
        if cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Err(PlatformError::Busy);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PlatformError::Busy);
        }
        let poll_budget = if cancellation.is_some() {
            remaining.min(Duration::from_millis(50))
        } else {
            remaining
        };
        let timeout_ms = poll_budget
            .as_nanos()
            .div_ceil(1_000_000)
            .clamp(1, i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: event,
            revents: 0,
        };
        // SAFETY: poll references one live descriptor and a finite timeout.
        let result = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            if cancellation.is_some() {
                continue;
            }
            return Err(PlatformError::Busy);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(PlatformError::Io);
        }
    }
}

#[cfg(unix)]
fn unix_write_all_until(
    stream: &mut std::os::unix::net::UnixStream,
    buffer: &[u8],
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<(), PlatformError> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PlatformError::Busy);
        }
        unix_wait_until(stream.as_raw_fd(), libc::POLLOUT, deadline, cancellation)?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err(PlatformError::Io),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Err(PlatformError::Busy);
            }
            Err(_) => return Err(PlatformError::Io),
        }
    }
    Ok(())
}

pub const MAX_BOOTSTRAP_FRAME_BYTES: usize = 16_384;

/// Native address published only through protected discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapEndpoint {
    Unix { path: PathBuf },
    WindowsPipe { name: String },
}

/// A connected channel whose remote owner was checked before use.
pub struct PeerChannel {
    #[cfg(unix)]
    stream: std::os::unix::net::UnixStream,
    #[cfg(windows)]
    stream: std::fs::File,
    peer: OwnerIdentity,
    deadline: Instant,
    cancellation: Option<Arc<AtomicBool>>,
}

impl PeerChannel {
    /// Return the identity reported by the operating system for this peer.
    pub fn peer_identity(&self) -> &OwnerIdentity {
        &self.peer
    }

    /// Stop frame I/O promptly when the owner sets this flag. Cancellation
    /// affects transport only; it does not undo an already committed request.
    pub fn cancel_when(&mut self, cancellation: Arc<AtomicBool>) {
        self.cancellation = Some(cancellation);
    }

    /// Read one bounded big-endian length-prefixed frame.
    pub fn read_frame(&mut self) -> Result<Vec<u8>, PlatformError> {
        let mut header = [0_u8; 4];
        #[cfg(unix)]
        unix_read_exact_until(
            &mut self.stream,
            &mut header,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        #[cfg(windows)]
        windows_read_exact(
            &self.stream,
            &mut header,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_BOOTSTRAP_FRAME_BYTES {
            return Err(PlatformError::InvalidFile);
        }
        let mut frame = vec![0; length];
        #[cfg(unix)]
        unix_read_exact_until(
            &mut self.stream,
            &mut frame,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        #[cfg(windows)]
        windows_read_exact(
            &self.stream,
            &mut frame,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        Ok(frame)
    }

    /// Write one bounded big-endian length-prefixed frame.
    pub fn write_frame(&mut self, frame: &[u8]) -> Result<(), PlatformError> {
        if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME_BYTES {
            return Err(PlatformError::InvalidFile);
        }
        let length = u32::try_from(frame.len()).map_err(|_| PlatformError::InvalidFile)?;
        // Send the header and payload in one bounded write. Splitting them
        // leaves a scheduling gap in which a fast peer can finish its response
        // and close before this caller has written the request body.
        let mut message = Vec::with_capacity(frame.len() + std::mem::size_of::<u32>());
        message.extend_from_slice(&length.to_be_bytes());
        message.extend_from_slice(frame);
        #[cfg(unix)]
        unix_write_all_until(
            &mut self.stream,
            &message,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        #[cfg(windows)]
        windows_write_all(
            &self.stream,
            &message,
            self.deadline,
            self.cancellation.as_deref(),
        )?;
        Ok(())
    }
}

/// Listener for explicit same-owner setup and readiness probes.
pub struct BootstrapListener {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    endpoint: BootstrapEndpoint,
    #[cfg(unix)]
    owner: OwnerIdentity,
    #[cfg(windows)]
    owner: OwnerIdentity,
    #[cfg(windows)]
    name: String,
}

impl BootstrapListener {
    /// Bind a private listener after the engine has acquired its authority.
    pub fn bind(root: &OwnedRoot, instance_id: &str) -> Result<Self, PlatformError> {
        let Some(suffix) = instance_id.strip_prefix("eng_") else {
            return Err(PlatformError::InvalidPath);
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PlatformError::InvalidPath);
        }
        root.ensure_private_directory(&RelativePath::parse("run")?)?;
        let owner = current_owner_identity()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let relative = RelativePath::parse("run/bootstrap.sock")?;
            let path = root.path_for_native_vfs(&relative);
            if path.as_os_str().as_encoded_bytes().len() >= 104 {
                return Err(PlatformError::InvalidPath);
            }
            remove_stale_socket(&path)?;
            let listener =
                std::os::unix::net::UnixListener::bind(&path).map_err(|_| PlatformError::Io)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| PlatformError::Io)?;
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| PlatformError::Io)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(PlatformError::UnsafeRoot);
            }
            listener
                .set_nonblocking(true)
                .map_err(|_| PlatformError::Io)?;
            Ok(Self {
                listener,
                endpoint: BootstrapEndpoint::Unix { path },
                owner,
            })
        }
        #[cfg(windows)]
        {
            let name = format!("\\\\.\\pipe\\dissect3d-bootstrap-{suffix}");
            let relative = RelativePath::parse("run")?;
            root.ensure_private_directory(&relative)?;
            // Reserve and validate the namespace while the engine already
            // owns its authority lease, then close this instance. Each accept
            // creates the next single-use pipe instance with the same DACL.
            drop(create_named_pipe(&name)?);
            Ok(Self {
                endpoint: BootstrapEndpoint::WindowsPipe { name: name.clone() },
                owner,
                name,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (root, owner);
            Err(PlatformError::UnsupportedRoot)
        }
    }

    /// Return the native endpoint clients may use after protected discovery.
    pub fn endpoint(&self) -> &BootstrapEndpoint {
        &self.endpoint
    }

    /// Accept one connection before the supplied monotonic deadline and reject
    /// any peer whose OS identity differs from this engine's owner.
    pub fn accept(&self, timeout: Duration) -> Result<PeerChannel, PlatformError> {
        self.accept_with_frame_timeout(timeout, timeout)
    }

    /// Poll the listener within `accept_timeout` while bounding accepted frame
    /// I/O independently. This keeps short lifecycle polling from becoming an
    /// accidentally short protocol-read timeout.
    pub fn accept_with_frame_timeout(
        &self,
        accept_timeout: Duration,
        frame_timeout: Duration,
    ) -> Result<PeerChannel, PlatformError> {
        #[cfg(unix)]
        {
            let deadline = Instant::now() + accept_timeout;
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        let peer = unix_peer_identity(&stream)?;
                        if peer != self.owner {
                            // A local peer that lacks the owner identity must
                            // not make the listener unavailable to a valid
                            // setup client.
                            if Instant::now() >= deadline {
                                return Err(PlatformError::Busy);
                            }
                            continue;
                        }
                        #[cfg(test)]
                        ACCEPTED_PEER_PAUSE.with(|pause| std::thread::sleep(pause.get()));
                        // The accept budget bounds listener polling. Once a
                        // verified peer is accepted, frame I/O owns its separate
                        // deadline, including after a scheduler pause here.
                        stream
                            .set_nonblocking(true)
                            .map_err(|_| PlatformError::Io)?;
                        let channel_deadline = Instant::now() + frame_timeout;
                        return Ok(PeerChannel {
                            cancellation: None,
                            stream,
                            peer,
                            deadline: channel_deadline,
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(PlatformError::Busy);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return Err(PlatformError::Io),
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let deadline = Instant::now() + accept_timeout;
            loop {
                let pipe = create_named_pipe(&self.name)?;
                loop {
                    let connected = unsafe {
                        windows_sys::Win32::System::Pipes::ConnectNamedPipe(
                            pipe.as_raw_handle().cast(),
                            std::ptr::null_mut(),
                        )
                    } != 0;
                    if connected
                        || std::io::Error::last_os_error().raw_os_error()
                            == Some(windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED as i32)
                    {
                        break;
                    }
                    let code = std::io::Error::last_os_error().raw_os_error();
                    if code != Some(windows_sys::Win32::Foundation::ERROR_PIPE_LISTENING as i32) {
                        return Err(PlatformError::Io);
                    }
                    if Instant::now() >= deadline {
                        return Err(PlatformError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let peer = windows_pipe_peer_identity(&pipe, false)?;
                if peer != self.owner {
                    drop(pipe);
                    if Instant::now() >= deadline {
                        return Err(PlatformError::UnsafeRoot);
                    }
                    continue;
                }
                #[cfg(test)]
                ACCEPTED_PEER_PAUSE.with(|pause| std::thread::sleep(pause.get()));
                // A verified connected pipe owns the independent frame budget.
                return Ok(PeerChannel {
                    cancellation: None,
                    stream: pipe,
                    peer,
                    deadline: Instant::now() + frame_timeout,
                });
            }
        }
    }
}

#[cfg(unix)]
fn remove_stale_socket(path: &std::path::Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1 =>
        {
            // The caller owns the engine lease before binding, so a matching
            // private socket cannot belong to another live engine instance.
            std::fs::remove_file(path).map_err(|_| PlatformError::Io)
        }
        Ok(_) => Err(PlatformError::UnsafeRoot),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PlatformError::Io),
    }
}

/// Connect and verify the server owner before allowing the caller to send a
/// secret-bearing enrollment frame.
pub fn connect(
    endpoint: &BootstrapEndpoint,
    expected_owner: &OwnerIdentity,
    timeout: Duration,
) -> Result<PeerChannel, PlatformError> {
    #[cfg(unix)]
    if let BootstrapEndpoint::Unix { path } = endpoint {
        let deadline = Instant::now() + timeout;
        let stream = unix_connect_until(path, deadline)?;
        let peer = unix_peer_identity(&stream)?;
        if &peer != expected_owner {
            return Err(PlatformError::UnsafeRoot);
        }
        return Ok(PeerChannel {
            cancellation: None,
            stream,
            peer,
            deadline,
        });
    }
    #[cfg(windows)]
    if let BootstrapEndpoint::WindowsPipe { .. } = endpoint {
        let BootstrapEndpoint::WindowsPipe { name } = endpoint else {
            unreachable!("the endpoint variant was checked")
        };
        let deadline = Instant::now() + timeout;
        loop {
            match open_named_pipe(name) {
                Ok(stream) => {
                    let peer = windows_pipe_peer_identity(&stream, true)?;
                    if &peer != expected_owner {
                        return Err(PlatformError::UnsafeRoot);
                    }
                    return Ok(PeerChannel {
                        cancellation: None,
                        stream,
                        peer,
                        deadline,
                    });
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.raw_os_error()
                            == Some(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32) =>
                {
                    if Instant::now() >= deadline {
                        return Err(PlatformError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(PlatformError::Io),
            }
        }
    }
    let _ = (endpoint, expected_owner, timeout);
    Err(PlatformError::UnsupportedRoot)
}

#[cfg(windows)]
fn create_named_pipe(name: &str) -> Result<std::fs::File, PlatformError> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE,
    };

    let descriptor = crate::windows::private_descriptor()?;
    let attributes = crate::windows::private_security_attributes(&descriptor);
    let wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: name and the protected current-user descriptor remain alive for
    // the call; the byte-mode pipe rejects remote clients and is nonblocking.
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            (MAX_BOOTSTRAP_FRAME_BYTES + 4) as u32,
            (MAX_BOOTSTRAP_FRAME_BYTES + 4) as u32,
            0,
            &attributes,
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(PlatformError::Io);
    }
    // SAFETY: CreateNamedPipeW returned a new owned kernel handle.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.cast()) })
}

#[cfg(windows)]
fn open_named_pipe(name: &str) -> Result<std::fs::File, std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, SetNamedPipeHandleState};

    let wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: the NUL-terminated name remains live for the call and the returned
    // handle is checked before ownership is transferred to File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new owned kernel handle.
    let file = unsafe { std::fs::File::from_raw_handle(handle.cast()) };
    let mode = PIPE_NOWAIT;
    // SAFETY: file owns a live named-pipe handle and mode is a valid input value.
    if unsafe {
        SetNamedPipeHandleState(
            std::os::windows::io::AsRawHandle::as_raw_handle(&file).cast(),
            &mode,
            std::ptr::null(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_pipe_peer_identity(
    pipe: &std::fs::File,
    query_server: bool,
) -> Result<OwnerIdentity, PlatformError> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0_u32;
    // SAFETY: the file owns a connected named-pipe handle and pid is writable.
    let success = unsafe {
        if query_server {
            windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                pipe.as_raw_handle().cast(),
                &mut pid,
            )
        } else {
            windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
                pipe.as_raw_handle().cast(),
                &mut pid,
            )
        }
    };
    if success == 0 || pid == 0 {
        return Err(PlatformError::Io);
    }
    crate::windows::process_owner_identity(pid)
}

#[cfg(windows)]
fn windows_read_exact(
    pipe: &std::fs::File,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<(), PlatformError> {
    use std::os::windows::io::AsRawHandle;
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline
            || cancellation.is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(PlatformError::Busy);
        }
        let mut read = 0_u32;
        // SAFETY: the handle is live and the remaining mutable slice is valid
        // for the requested length; ReadFile writes at most that many bytes.
        let success = unsafe {
            windows_sys::Win32::Storage::FileSystem::ReadFile(
                pipe.as_raw_handle().cast(),
                buffer[offset..].as_mut_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if success != 0 && read > 0 {
            offset += read as usize;
        } else {
            let code = std::io::Error::last_os_error().raw_os_error();
            if code != Some(windows_sys::Win32::Foundation::ERROR_NO_DATA as i32)
                && code != Some(windows_sys::Win32::Foundation::ERROR_PIPE_LISTENING as i32)
            {
                return Err(PlatformError::Io);
            }
            if Instant::now() >= deadline {
                return Err(PlatformError::Busy);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_write_all(
    pipe: &std::fs::File,
    buffer: &[u8],
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<(), PlatformError> {
    use std::os::windows::io::AsRawHandle;
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline
            || cancellation.is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(PlatformError::Busy);
        }
        let mut written = 0_u32;
        // SAFETY: the handle is live and the remaining immutable slice is valid
        // for the requested length; WriteFile reads but does not retain it.
        let success = unsafe {
            windows_sys::Win32::Storage::FileSystem::WriteFile(
                pipe.as_raw_handle().cast(),
                buffer[offset..].as_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if success != 0 && written > 0 {
            offset += written as usize;
        } else {
            let code = std::io::Error::last_os_error().raw_os_error();
            if code != Some(windows_sys::Win32::Foundation::ERROR_NO_DATA as i32) {
                return Err(PlatformError::Io);
            }
            if Instant::now() >= deadline {
                return Err(PlatformError::Busy);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unix_peer_identity(
    stream: &std::os::unix::net::UnixStream,
) -> Result<OwnerIdentity, PlatformError> {
    use std::os::fd::AsFd;
    let credentials =
        rustix::net::sockopt::socket_peercred(stream.as_fd()).map_err(|_| PlatformError::Io)?;
    Ok(OwnerIdentity::UnixUid(credentials.uid.as_raw()))
}

#[cfg(target_os = "macos")]
fn unix_peer_identity(
    stream: &std::os::unix::net::UnixStream,
) -> Result<OwnerIdentity, PlatformError> {
    use std::os::fd::AsRawFd;
    let mut uid = 0_u32;
    let mut gid = 0_u32;
    // SAFETY: `stream` owns a live Unix socket and both credential outputs are
    // writable values with the native uid/gid representation used by macOS.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(PlatformError::Io);
    }
    let _ = gid;
    Ok(OwnerIdentity::UnixUid(uid))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn unix_peer_identity(
    _stream: &std::os::unix::net::UnixStream,
) -> Result<OwnerIdentity, PlatformError> {
    Err(PlatformError::UnsupportedRoot)
}

#[cfg(all(test, any(unix, windows)))]
thread_local! {
    static ACCEPTED_PEER_PAUSE: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}

#[cfg(all(test, unix))]
mod accept_boundary_tests {
    use super::*;
    use crate::{OwnedRoot, RootPurpose, current_owner_identity};

    #[test]
    fn verified_accepted_peer_keeps_its_independent_frame_budget() {
        let parent = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
                .unwrap();
        let listener =
            BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef").unwrap();
        let owner = current_owner_identity().unwrap();
        let mut client = connect(listener.endpoint(), &owner, Duration::from_secs(2)).unwrap();
        client.write_frame(b"ready peer").unwrap();
        // Model a scheduler pause after the kernel accepted and verified the
        // peer. The listener's polling budget no longer owns this channel.
        ACCEPTED_PEER_PAUSE.with(|pause| pause.set(Duration::from_millis(150)));
        let accepted =
            listener.accept_with_frame_timeout(Duration::from_millis(100), Duration::from_secs(1));
        ACCEPTED_PEER_PAUSE.with(|pause| pause.set(Duration::ZERO));
        let mut channel = accepted.expect("accepted verified peer receives its frame budget");
        assert_eq!(channel.read_frame().unwrap(), b"ready peer");
        channel.write_frame(b"confirmed").unwrap();
        assert_eq!(client.read_frame().unwrap(), b"confirmed");
    }
}

#[cfg(all(test, windows))]
mod pipe_accept_boundary_tests {
    use super::*;
    use crate::{OwnedRoot, RootPurpose, current_owner_identity};

    #[test]
    fn verified_connected_pipe_keeps_its_independent_frame_budget() {
        let parent = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
                .unwrap();
        let listener =
            BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef").unwrap();
        let endpoint = listener.endpoint().clone();
        let owner = current_owner_identity().unwrap();
        let server = std::thread::spawn(move || {
            ACCEPTED_PEER_PAUSE.with(|pause| pause.set(Duration::from_millis(1100)));
            let accepted =
                listener.accept_with_frame_timeout(Duration::from_secs(1), Duration::from_secs(1));
            ACCEPTED_PEER_PAUSE.with(|pause| pause.set(Duration::ZERO));
            let mut channel = accepted.expect("verified connected pipe receives frame budget");
            assert_eq!(channel.read_frame().unwrap(), b"ready peer");
            channel.write_frame(b"confirmed").unwrap();
        });
        let mut client = connect(&endpoint, &owner, Duration::from_secs(3)).unwrap();
        client.write_frame(b"ready peer").unwrap();
        assert_eq!(client.read_frame().unwrap(), b"confirmed");
        server.join().unwrap();
    }
}
