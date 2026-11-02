#![cfg(unix)]

use dissect3d_platform::{
    AuthorityLease, BootstrapEndpoint, BootstrapListener, OwnedRoot, PlatformError, RootPurpose,
    connect_bootstrap, current_owner_identity,
};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn invalid_instance_identity_is_refused_before_creating_runtime_paths() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");

    assert!(matches!(
        BootstrapListener::bind(&root, "invalid"),
        Err(PlatformError::InvalidPath)
    ));
    assert!(!root.path().join("run").exists());
}

#[test]
fn native_channel_checks_peer_and_round_trips_one_frame() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("current owner");
    let server_owner = owner.clone();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(2)).expect("peer");
        assert_eq!(channel.peer_identity(), &server_owner);
        let request = channel.read_frame().expect("request frame");
        channel.write_frame(&request).expect("response frame");
    });

    let mut client =
        connect_bootstrap(&endpoint, &owner, Duration::from_secs(2)).expect("verified server peer");
    client
        .write_frame(b"{\"kind\":\"probe\"}")
        .expect("request");
    assert_eq!(
        client.read_frame().expect("response"),
        b"{\"kind\":\"probe\"}"
    );
    server.join().expect("server thread");
}

#[test]
fn accepted_channel_can_block_for_a_frame_sent_after_reading_starts() {
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
        assert_eq!(
            channel.read_frame().expect("delayed request frame"),
            b"request"
        );
    });

    let mut client =
        connect_bootstrap(&endpoint, &owner, Duration::from_secs(2)).expect("verified server peer");
    reading_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server started reading before client writes");
    client.write_frame(b"request").expect("request");
    server.join().expect("server thread");
}

#[test]
fn short_accept_poll_does_not_shorten_accepted_frame_deadline() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("e"), RootPurpose::EngineData)
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
            .expect("accepted peer");
        accepted_tx.send(()).expect("accepted signal");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            channel
                .read_frame()
                .expect("frame within independent budget"),
            b"late"
        );
    });
    let mut client =
        connect_bootstrap(&endpoint, &owner, Duration::from_secs(2)).expect("verified server peer");
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("accepted signal");
    std::thread::sleep(Duration::from_millis(300));
    client
        .write_frame(b"late")
        .expect("frame after accept poll");
    server.join().expect("server thread");
}

#[cfg(unix)]
#[test]
fn client_refuses_a_server_with_a_different_owner_before_writing() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();

    let owner = current_owner_identity().expect("current owner");
    let wrong_owner = match owner {
        dissect3d_platform::OwnerIdentity::UnixUid(uid) => {
            dissect3d_platform::OwnerIdentity::UnixUid(uid ^ 1)
        }
        dissect3d_platform::OwnerIdentity::WindowsSid(_) => unreachable!("Unix test target"),
    };
    assert!(matches!(
        connect_bootstrap(&endpoint, &wrong_owner, Duration::from_secs(2)),
        Err(PlatformError::UnsafeRoot)
    ));
    drop(listener);
}

#[cfg(unix)]
#[test]
fn native_channel_reassembles_fragmented_frame_bytes() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let BootstrapEndpoint::Unix { path } = listener.endpoint() else {
        unreachable!("Unix target publishes a Unix socket")
    };
    let path = path.clone();
    let mut client = UnixStream::connect(path).expect("connect local socket");
    client
        .write_all(&10_u32.to_be_bytes()[..2])
        .expect("write partial length prefix");
    client
        .write_all(&10_u32.to_be_bytes()[2..])
        .expect("finish length prefix");
    client.write_all(b"fragmented").expect("write payload");
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(2)).expect("peer");
        assert_eq!(
            channel.read_frame().expect("fragmented frame"),
            b"fragmented"
        );
    });
    server.join().expect("server thread");
}

#[test]
fn oversized_frame_is_rejected_before_payload_allocation() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let BootstrapEndpoint::Unix { path } = listener.endpoint() else {
        unreachable!("Unix target publishes a Unix socket")
    };
    let path = path.clone();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(2)).expect("peer");
        assert_eq!(channel.read_frame(), Err(PlatformError::InvalidFile));
    });

    let mut client = UnixStream::connect(path).expect("connect local socket");
    client
        .write_all(&16_385_u32.to_be_bytes())
        .expect("oversized length");
    server.join().expect("server thread");
}

#[test]
fn incomplete_frame_read_is_bounded_by_channel_deadline() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let BootstrapEndpoint::Unix { path } = listener.endpoint() else {
        unreachable!("Unix target publishes a Unix socket")
    };
    let path = path.clone();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_millis(200)).expect("peer");
        let started = std::time::Instant::now();
        let result = channel.read_frame();
        let elapsed = started.elapsed();
        assert_eq!(result, Err(PlatformError::Busy));
        assert!(
            elapsed >= Duration::from_millis(150),
            "incomplete frame failed immediately instead of timing out: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "incomplete frame exceeded its bounded read timeout: {elapsed:?}"
        );
    });
    let mut client = UnixStream::connect(path).expect("connect local socket");
    client.write_all(&[0, 0]).expect("partial length prefix");
    server.join().expect("server thread");
}

#[test]
fn slow_frame_trickle_cannot_extend_one_channel_deadline() {
    let parent = TempDir::new().expect("temporary parent");
    let root = OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("bootstrap listener");
    let BootstrapEndpoint::Unix { path } = listener.endpoint() else {
        unreachable!("Unix target publishes a Unix socket")
    };
    let path = path.clone();
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_millis(180)).expect("peer");
        let started = std::time::Instant::now();
        assert_eq!(channel.read_frame(), Err(PlatformError::Busy));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(140),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_millis(350), "elapsed: {elapsed:?}");
    });
    let mut client = UnixStream::connect(path).expect("connect local socket");
    client.write_all(&[0]).expect("first header byte");
    std::thread::sleep(Duration::from_millis(100));
    let _ = client.write_all(&[0]);
    std::thread::sleep(Duration::from_millis(100));
    let _ = client.write_all(&[0, 5]);
    server.join().expect("server thread");
}
