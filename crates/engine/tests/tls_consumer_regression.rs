use std::sync::Arc;

use dissect3d_engine::{CorePolicy, HttpServer, Store};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RootPurpose};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[tokio::test]
async fn reopening_tls_configuration_reuses_the_protected_installation_ca() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");

    let first = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("first HTTPS configuration");
    let (first_ca, first_pin) = first.trust_anchor();
    let first_ca = first_ca.to_vec();
    let first_pin = *first_pin;
    drop(first);

    let second = HttpServer::bind(&tls_root, store, CorePolicy::default())
        .await
        .expect("reopened HTTPS configuration");
    let (second_ca, second_pin) = second.trust_anchor();

    assert_eq!(second_ca, first_ca);
    assert_eq!(second_pin, &first_pin);
    assert_eq!(Sha256::digest(second_ca).as_slice(), first_pin);
}
