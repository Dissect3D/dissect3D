#![cfg(windows)]

use dissect3d_platform::{
    AuthorityLease, BootstrapEndpoint, BootstrapListener, OwnedRoot, RootPurpose,
    connect_bootstrap, current_owner_identity,
};
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn named_pipe_checks_peer_and_round_trips_one_frame() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    assert!(matches!(endpoint, BootstrapEndpoint::WindowsPipe { .. }));
    let owner = current_owner_identity().expect("current owner");
    let server_owner = owner.clone();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(2)).expect("peer");
        assert_eq!(channel.peer_identity(), &server_owner);
        let frame = channel.read_frame().expect("request frame");
        channel.write_frame(&frame).expect("response frame");
    });

    let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("verified named-pipe server");
    client.write_frame(b"probe").expect("request");
    assert_eq!(client.read_frame().expect("response"), b"probe");
    server.join().expect("server thread");
}

#[test]
fn named_pipe_can_read_before_client_sends_a_frame() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("current owner");
    let (reading_tx, reading_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(2)).expect("peer");
        reading_tx.send(()).expect("signal reader started");
        assert_eq!(channel.read_frame().expect("delayed frame"), b"request");
    });

    let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("verified named-pipe server");
    reading_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server started reading before client writes");
    client.write_frame(b"request").expect("delayed request");
    server.join().expect("server thread");
}

#[test]
fn short_pipe_accept_poll_does_not_shorten_accepted_frame_deadline() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("current owner");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut channel = listener
            .accept_with_frame_timeout(Duration::from_millis(200), Duration::from_secs(1))
            .expect("accepted pipe peer");
        accepted_tx.send(()).expect("accepted signal");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            channel
                .read_frame()
                .expect("frame within independent budget"),
            b"late"
        );
    });
    let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("verified named-pipe server");
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("accepted signal");
    std::thread::sleep(Duration::from_millis(300));
    client
        .write_frame(b"late")
        .expect("frame after accept poll");
    server.join().expect("server thread");
}

#[test]
fn incomplete_named_pipe_frame_times_out_instead_of_failing_immediately() {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, SetNamedPipeHandleState};

    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let BootstrapEndpoint::WindowsPipe { name } = listener.endpoint() else {
        unreachable!("Windows publishes a named pipe")
    };
    let name: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let server = std::thread::spawn(move || {
        let mut channel = listener
            .accept_with_frame_timeout(Duration::from_secs(2), Duration::from_millis(250))
            .expect("peer");
        let started = std::time::Instant::now();
        let result = channel.read_frame();
        let elapsed = started.elapsed();
        assert_eq!(result, Err(dissect3d_platform::PlatformError::Busy));
        assert!(
            elapsed >= Duration::from_millis(150),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(1), "elapsed: {elapsed:?}");
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let handle = loop {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            break handle;
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(2 | 231)) || std::time::Instant::now() >= deadline {
            panic!("connect test pipe before deadline: {error}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut client = unsafe { std::fs::File::from_raw_handle(handle.cast()) };
    let mode = PIPE_NOWAIT;
    assert_ne!(
        unsafe {
            SetNamedPipeHandleState(
                std::os::windows::io::AsRawHandle::as_raw_handle(&client).cast(),
                &mode,
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    client.write_all(&[0, 0]).expect("partial length prefix");
    server.join().expect("server thread");
}

#[test]
fn available_pipe_bytes_do_not_bypass_an_expired_frame_deadline() {
    let temp = TempDir::new().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData).unwrap();
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef").unwrap();
    let endpoint = listener.endpoint().clone();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
    let (written_tx, written_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut channel = listener
            .accept_with_frame_timeout(Duration::from_secs(2), Duration::from_millis(50))
            .unwrap();
        accepted_tx.send(()).unwrap();
        written_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            channel.read_frame().is_err(),
            "expired read accepted buffered bytes"
        );
        assert!(
            channel.write_frame(b"late").is_err(),
            "expired write succeeded"
        );
    });
    let owner = current_owner_identity().unwrap();
    let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2)).unwrap();
    accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    client.write_frame(b"buffered").unwrap();
    written_tx.send(()).unwrap();
    server.join().unwrap();
}
