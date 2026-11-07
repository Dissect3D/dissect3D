use super::*;
use crate::store::inputs::{InputCleanupKind, PinnedInputSet};
use dissect3d_api::{EnrollmentId, TokenDigest};
use dissect3d_platform::{AuthorityLease, RootPurpose};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn exhausted_record_capacity_identifies_its_limit_without_a_new_reservation() {
    let fixture = InputFixture::new();
    let receipt = fixture.capture(b"seed");
    let mut db = Connection::open(fixture.root_path.join("metadata.sqlite3")).unwrap();
    let transaction = db.transaction().unwrap();
    for index in 0..MAX_INPUT_ROWS - 1 {
        transaction.execute(
            "INSERT INTO captured_inputs(input_id,client_id,media_type,byte_length,sha256,completed_at_ms,expires_at_ms)
             SELECT ?1,client_id,media_type,byte_length,sha256,completed_at_ms,expires_at_ms FROM captured_inputs WHERE input_id=?2",
            rusqlite::params![format!("inp_{index:032x}"), receipt.identity.input_id.as_str()],
        ).unwrap();
    }
    transaction.commit().unwrap();
    assert!(matches!(
        fixture.store().reserve_upload(
            fixture.context.clone(),
            1,
            "application/octet-stream".to_owned(),
            fixture.root.available_space_bytes().unwrap()
        ),
        Err(CoreError::CapacityExceeded("staged_input_records_max"))
    ));
    let reservations: i64 = db
        .query_row("SELECT count(*) FROM input_upload_reservations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(reservations, 0);
}

#[test]
fn cleanup_advances_past_an_entire_batch_of_pinned_expired_inputs() {
    let fixture = InputFixture::new();
    let mut receipts = (0..65)
        .map(|_| fixture.capture(b"bounded input"))
        .collect::<Vec<_>>();
    receipts.sort_by(|left, right| {
        (left.expires_at_ms.get(), left.identity.input_id.as_str())
            .cmp(&(right.expires_at_ms.get(), right.identity.input_id.as_str()))
    });
    let now = receipts.last().unwrap().expires_at_ms.get() as i64;
    let ids = receipts[..64]
        .iter()
        .map(|receipt| receipt.identity.input_id.clone())
        .collect();
    let _pins = fixture
        .store()
        .pin_verified_inputs(fixture.context.clone(), ids)
        .unwrap();
    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(now)
            .unwrap()
            .is_empty()
    );
    let next = fixture.store().claim_input_cleanup_at(now).unwrap();
    assert_eq!(
        next.len(),
        1,
        "later expired inputs must not starve behind pinned rows"
    );
    assert_eq!(next[0].input_id, receipts[64].identity.input_id);
}

struct InputFixture {
    _parent: TempDir,
    root_path: PathBuf,
    root: OwnedRoot,
    store: Option<Store>,
    context: AuthContext,
}

impl InputFixture {
    fn new() -> Self {
        let parent = tempfile::tempdir().expect("temporary root parent");
        let root_path = parent.path().join("engine");
        let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
            .expect("private engine root");
        let lease = AuthorityLease::acquire(&root).expect("authority lease");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("store actor");
        let identity = store.identity().expect("store identity");
        let client_id =
            ClientId::parse("cli_2223456789abcdef0123456789abcdef").expect("client identity");
        let token_digest = TokenDigest::new(Sha256::digest([0x42; 32]).into());
        store
            .enroll(VerifiedEnrollment::new_submission_access(
                current_owner_identity().expect("owner identity"),
                identity.installation_id,
                identity.instance_id,
                EnrollmentId::parse("enr_2223456789abcdef0123456789abcdef")
                    .expect("enrollment identity"),
                client_id.clone(),
                token_digest.clone(),
            ))
            .expect("submission enrollment");
        let context = store
            .authenticate(client_id, token_digest.clone())
            .expect("submission authorization");
        let root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("file root");
        Self {
            _parent: parent,
            root_path,
            root,
            store: Some(store),
            context,
        }
    }

    fn store(&self) -> &Store {
        self.store.as_ref().expect("live store")
    }

    fn restart(&mut self) {
        drop(self.store.take());
        let root = OwnedRoot::open(&self.root_path, RootPurpose::EngineData)
            .expect("reopened engine root");
        let lease = AuthorityLease::acquire(&root).expect("reacquired authority lease");
        self.store =
            Some(Store::open(root, lease, &CorePolicy::default()).expect("reopened store"));
    }

    fn capture(&self, content: &[u8]) -> InputReceipt {
        let reservation = self
            .store()
            .reserve_upload(
                self.context.clone(),
                content.len() as u64,
                "application/octet-stream".to_owned(),
                self.root.available_space_bytes().expect("free space"),
            )
            .expect("upload reservation");
        let staged = RelativePath::parse(format!(
            "inputs/staging/{}.part",
            reservation.input_id.as_str()
        ))
        .expect("staging path");
        let final_path =
            RelativePath::parse(format!("inputs/data/{}.bin", reservation.input_id.as_str()))
                .expect("captured path");
        let mut writer = self.root.begin_input(&staged).expect("staging writer");
        writer.write_chunk(content).expect("captured bytes");
        let file = writer.finish(&final_path).expect("durable input");
        self.store()
            .complete_upload(
                self.context.clone(),
                reservation,
                DurableInput {
                    file,
                    sha256: Sha256::digest(content).into(),
                },
            )
            .expect("input receipt")
    }
}

#[test]
fn abandoned_upload_is_reclaimed_only_after_its_live_handle_and_file_are_gone() {
    let fixture = InputFixture::new();
    let reservation = fixture
        .store()
        .reserve_upload(
            fixture.context.clone(),
            8,
            "application/octet-stream".to_owned(),
            fixture.root.available_space_bytes().expect("free space"),
        )
        .expect("upload reservation");
    let input_id = reservation.input_id.clone();
    let staged = RelativePath::parse(format!("inputs/staging/{}.part", input_id.as_str()))
        .expect("staging path");
    let mut writer = fixture.root.begin_input(&staged).expect("staging writer");
    writer
        .write_chunk(b"partial")
        .expect("partial upload bytes");
    drop(writer);

    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(now_ms().expect("clock"))
            .expect("live reservation is retained")
            .is_empty()
    );
    drop(reservation);

    let claim = fixture
        .store()
        .claim_input_cleanup_at(now_ms().expect("clock"))
        .expect("abandoned reservation is claimed")
        .pop()
        .expect("one cleanup claim");
    assert_eq!(claim.input_id, input_id);
    assert!(matches!(claim.kind, InputCleanupKind::Reservation { .. }));
    fixture
        .root
        .remove_durable(&staged)
        .expect("staging deletion is durable");
    fixture
        .store()
        .confirm_input_cleanup(claim)
        .expect("reservation charge is released after deletion");
    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(now_ms().expect("clock"))
            .expect("no remaining incomplete reservation")
            .is_empty()
    );
}

#[test]
fn expiry_waits_for_pins_and_retries_deleting_state_after_restart() {
    let mut fixture = InputFixture::new();
    let receipt = fixture.capture(b"immutable staged bytes");
    assert_eq!(
        receipt.expires_at_ms.get() - receipt.completed_at_ms.get(),
        UPLOAD_TTL_MS as u64
    );
    let expiry = i64::try_from(receipt.expires_at_ms.get()).expect("expiry timestamp");
    let input_id = receipt.identity.input_id.clone();
    let data = RelativePath::parse(format!("inputs/data/{}.bin", input_id.as_str()))
        .expect("captured path");
    let pins: PinnedInputSet = fixture
        .store()
        .pin_verified_inputs(fixture.context.clone(), vec![input_id.clone()])
        .expect("input validation pin");

    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(expiry - 1)
            .expect("not yet expired")
            .is_empty()
    );
    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(expiry - 100)
            .expect("backward wall time does not move the expiry clock")
            .is_empty()
    );
    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(expiry)
            .expect("pin delays deletion")
            .is_empty()
    );
    drop(pins);

    let claim = fixture
        .store()
        .claim_input_cleanup_at(expiry)
        .expect("expired input is claimed")
        .pop()
        .expect("one expired input");
    assert_eq!(claim.input_id, input_id);
    assert!(matches!(claim.kind, InputCleanupKind::Captured));
    fixture
        .root
        .remove_durable(&data)
        .expect("file deletion before confirmation");

    fixture.restart();
    let resumed = fixture
        .store()
        .claim_input_cleanup_at(expiry)
        .expect("deleting record survives restart")
        .pop()
        .expect("deletion is resumed");
    assert_eq!(resumed.input_id, input_id);
    fixture
        .root
        .remove_durable(&data)
        .expect("already removed is confirmed absent");
    fixture
        .store()
        .confirm_input_cleanup(resumed)
        .expect("expired metadata is removed after confirmed absence");
    assert!(
        fixture
            .store()
            .claim_input_cleanup_at(expiry)
            .expect("no expired record remains")
            .is_empty()
    );
}
