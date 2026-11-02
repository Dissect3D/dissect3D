#![cfg(any(unix, windows))]

use dissect3d_platform::{
    BootstrapListener, OwnedRoot, PlatformError, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[test]
fn owner_cancellation_interrupts_a_stalled_native_frame() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef").unwrap();
    let endpoint = listener.endpoint().clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let server_cancelled = cancelled.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut channel = listener
            .accept_with_frame_timeout(Duration::from_secs(2), Duration::from_secs(5))
            .unwrap();
        channel.cancel_when(server_cancelled);
        ready_tx.send(()).unwrap();
        assert_eq!(channel.read_frame(), Err(PlatformError::Busy));
    });
    let _client = connect_bootstrap(
        &endpoint,
        &current_owner_identity().unwrap(),
        Duration::from_secs(2),
    )
    .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    cancelled.store(true, Ordering::Release);
    server.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}
