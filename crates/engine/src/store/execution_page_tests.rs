//! WE-P03 creator-scoped execution pages and the legacy-list guard (2026-11-17).
//! Dispatch stays inactive; non-queued states come from the private dispatch and
//! cancellation seams, and other-creator rows from isolated SQL setup.
use super::retry_tests::{accept, authorize, canceled_source, db, dispatch, prerequisites};
use super::*;
use crate::submission::SubmissionError;

fn page(
    f: &Fixture,
    auth: &AuthContext,
    limit: Option<u8>,
    cursor: Option<String>,
) -> Result<ExecutionJobPage, SubmissionError> {
    f.store
        .execution_job_page(auth.clone(), JobsQuery { limit, cursor })
}
fn raw_page(f: &Fixture, auth: &AuthContext, limit: u8) -> execution_reads::RawPage {
    f.store
        .request(|reply| {
            Command::ExecutionRead(execution_reads::ReadCommand::Page(
                auth.clone(),
                JobsQuery {
                    limit: Some(limit),
                    cursor: None,
                },
                reply,
            ))
        })
        .unwrap()
}
fn ids(page: &ExecutionJobPage) -> Vec<JobId> {
    page.items.iter().map(|item| item.job_id.clone()).collect()
}
fn retry(f: &Fixture, auth: &AuthContext, key: &str, source: &JobId) -> JobId {
    f.store
        .retry_job(
            auth.clone(),
            IdempotencyKey::parse(key).unwrap(),
            source.clone(),
            prerequisites(f),
        )
        .unwrap()
        .job_id
}
fn stranger(f: &Fixture) -> AuthContext {
    let identity = f.store.identity().unwrap();
    let client = ClientId::parse("cli_44444444444444444444444444444444").unwrap();
    let digest = TokenDigest::new([4; 32]);
    f.store
        .enroll(VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse("enr_44444444444444444444444444444444").unwrap(),
            client.clone(),
            digest.clone(),
        ))
        .unwrap();
    f.store.authenticate(client, digest).unwrap()
}
/// Isolated setup: hand an accepted job to another creator.
fn give(f: &Fixture, job: &JobId, to: &AuthContext) {
    db(f)
        .execute(
            "UPDATE jobs SET client_id=?2 WHERE job_id=?1",
            [job.as_str(), to.client_id.as_str()],
        )
        .unwrap();
}
pub(super) fn reopen(f: Fixture) -> Fixture {
    let Fixture {
        _parent,
        root,
        store,
        auth,
        prepared,
    } = f;
    drop(store);
    let reopened = OwnedRoot::open(root.path(), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&reopened).unwrap();
    Fixture {
        _parent,
        root,
        store: Store::open(reopened, lease, &CorePolicy::default()).unwrap(),
        auth,
        prepared,
    }
}

#[test]
fn page_reads_fresh_state_and_immediate_retry_links_exactly_like_the_single_read() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let queued = accept(&f, "queued").job_id;
    let running = accept(&f, "running").job_id;
    let attempt = dispatch(&f, &running).attempt_id;
    let canceled = canceled_source(&f, &auth, "canceled");
    let first_retry = retry(&f, &auth, "retry-one", &canceled);
    f.store
        .cancel_execution_job(auth.clone(), first_retry.clone())
        .unwrap();
    let second_retry = retry(&f, &auth, "retry-two", &first_retry);
    // An active cancellation moves the running job to a later revision.
    assert_eq!(
        f.store
            .cancel_execution_job(auth.clone(), running.clone())
            .unwrap(),
        "requested"
    );

    let listed = page(&f, &auth, None, None).unwrap();
    assert_eq!(
        ids(&listed),
        [
            queued.clone(),
            running.clone(),
            canceled.clone(),
            first_retry.clone(),
            second_retry.clone()
        ]
    );
    assert!(!listed.truncated);
    assert_eq!(listed.next_cursor, None);
    assert_eq!(listed.api_version, "1.0");
    assert_eq!(listed.job_contract, JOB_CONTRACT);
    listed.validate().unwrap();
    // One mapping: every item equals the single read's summary at the same revision.
    for item in &listed.items {
        let single = f
            .store
            .execution_job_snapshot(auth.clone(), item.job_id.clone())
            .unwrap();
        assert_eq!(item, &single.summary);
        assert!(item.result_ids.is_empty(), "no result before publication");
    }
    let by_id = |id: &JobId| listed.items.iter().find(|i| &i.job_id == id).unwrap();
    let active = by_id(&running);
    assert_eq!(active.state, ExecutionJobState::CancelRequested);
    assert_eq!(active.snapshot_revision, 3);
    assert_eq!(active.attempt_id.as_deref(), Some(attempt.as_str()));
    assert!(active.cancellation.requested);
    assert_eq!(by_id(&queued).snapshot_revision, 1);
    assert_eq!(by_id(&canceled).state, ExecutionJobState::Canceled);
    assert_eq!(by_id(&canceled).retry_of, None);
    // Retry links name the immediate source only; no chain walking.
    assert_eq!(by_id(&first_retry).retry_of.as_ref(), Some(&canceled));
    assert_eq!(by_id(&second_retry).retry_of.as_ref(), Some(&first_retry));
}

#[test]
fn page_is_creator_scoped_in_sql_and_other_creators_never_move_the_cursor() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let other = stranger(&f);
    let a = accept(&f, "a").job_id;
    let b = accept(&f, "b").job_id;
    let c = accept(&f, "c").job_id;
    let d = accept(&f, "d").job_id;
    give(&f, &b, &other);
    give(&f, &d, &other);

    let first = page(&f, &auth, Some(1), None).unwrap();
    assert_eq!(ids(&first), std::slice::from_ref(&a));
    assert!(first.truncated);
    let cursor = first.next_cursor.clone().unwrap();
    // Another creator's later job neither appears nor moves this cursor's bounds.
    let e = accept(&f, "e").job_id;
    give(&f, &e, &other);
    let second = page(&f, &auth, Some(1), Some(cursor.clone())).unwrap();
    assert_eq!(ids(&second), std::slice::from_ref(&c));
    assert!(!second.truncated);
    assert_eq!(second.next_cursor, None);
    // A job of the owner's accepted after the first page is above its high water.
    let late = accept(&f, "late").job_id;
    assert_eq!(
        ids(&page(&f, &auth, Some(1), Some(cursor.clone())).unwrap()),
        std::slice::from_ref(&c)
    );
    assert_eq!(ids(&page(&f, &auth, None, None).unwrap()), [a, c, late]);
    // The other creator sees only its own rows, and cannot use the owner's cursor.
    assert_eq!(ids(&page(&f, &other, None, None).unwrap()), [b, d, e]);
    assert_eq!(
        page(&f, &other, Some(1), Some(cursor)).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
}

#[test]
fn page_limits_and_cursor_are_bounded_versioned_and_collection_bound() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let accepted: Vec<JobId> = (0..21)
        .map(|n| accept(&f, &format!("job-{n}")).job_id)
        .collect();
    for limit in [0, 101] {
        assert_eq!(
            page(&f, &auth, Some(limit), None).unwrap_err().code,
            ErrorCode::InvalidRequest,
            "{limit}"
        );
    }
    assert_eq!(page(&f, &auth, Some(100), None).unwrap().items.len(), 21);
    // Default page size is 20.
    let first = page(&f, &auth, None, None).unwrap();
    assert_eq!(ids(&first), accepted[..20]);
    assert!(first.truncated);
    let cursor = first.next_cursor.clone().unwrap();
    assert!(cursor.len() <= 1024);
    let rest = page(&f, &auth, None, Some(cursor.clone())).unwrap();
    assert_eq!(ids(&rest), accepted[20..]);
    // The cursor is bound to its limit and to its exact encoding.
    assert_eq!(
        page(&f, &auth, Some(19), Some(cursor.clone()))
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    for tampered in [format!("{cursor}A"), "x".repeat(1025), String::new()] {
        assert_eq!(
            page(&f, &auth, None, Some(tampered)).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    // Neither collection accepts the other's cursor.
    let queued = f
        .store
        .list_jobs(
            auth.clone(),
            JobsQuery {
                limit: None,
                cursor: None,
            },
        )
        .unwrap()
        .next_cursor
        .unwrap();
    assert_eq!(
        page(&f, &auth, None, Some(queued)).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        f.store
            .list_jobs(
                auth.clone(),
                JobsQuery {
                    limit: None,
                    cursor: Some(cursor.clone()),
                },
            )
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    // The cursor is bound to this engine instance.
    let f = reopen(f);
    let auth = f
        .store
        .authenticate(auth.client_id, fixture_credentials().1)
        .unwrap();
    assert_eq!(
        page(&f, &auth, None, Some(cursor)).unwrap_err().code,
        ErrorCode::JobCursorExpired
    );
}

#[test]
fn response_byte_packing_stops_before_the_limit_and_refuses_an_item_that_cannot_fit() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let jobs: Vec<JobId> = (0..3)
        .map(|n| accept(&f, &format!("pack-{n}")).job_id)
        .collect();
    let full = execution_reads::pack(&raw_page(&f, &auth, 3)).unwrap();
    assert_eq!(ids(&full), jobs);
    let full_bytes = serde_json::to_vec(&full).unwrap().len();

    let mut raw = raw_page(&f, &auth, 3);
    raw.response_limit = full_bytes - 1;
    let packed = execution_reads::pack(&raw).unwrap();
    assert_eq!(ids(&packed), jobs[..2]);
    assert!(packed.truncated);
    assert!(serde_json::to_vec(&packed).unwrap().len() < full_bytes);
    // The honest cursor resumes exactly after the last packed item.
    let rest = page(&f, &auth, Some(3), packed.next_cursor.clone()).unwrap();
    assert_eq!(ids(&rest), jobs[2..]);

    let mut raw = raw_page(&f, &auth, 3);
    raw.response_limit = 64;
    let refused = execution_reads::pack(&raw).unwrap_err();
    assert_eq!(refused.code, ErrorCode::CapacityExceeded);
    assert_eq!(refused.limit, Some("control_response_bytes"));
}

#[test]
fn corrupt_or_unpublishable_stored_rows_fail_the_page_closed_instead_of_being_skipped() {
    for (column, value, expected) in [
        ("state", "bogus", ErrorCode::StoreUnavailable),
        ("phase", "", ErrorCode::StoreUnavailable),
        ("cleanup_status", "maybe", ErrorCode::StoreUnavailable),
        // RP-P03 supplies real result IDs; success is never shown with none.
        ("state", "succeeded", ErrorCode::Busy),
    ] {
        let f = Fixture::new();
        let auth = authorize(&f);
        accept(&f, "fine");
        let bad = accept(&f, "bad").job_id;
        let db = db(&f);
        db.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        db.execute(
            &format!("UPDATE job_execution SET {column}=?2 WHERE job_id=?1"),
            [bad.as_str(), value],
        )
        .unwrap();
        assert_eq!(
            page(&f, &auth, None, None).unwrap_err().code,
            expected,
            "{column}={value}"
        );
    }
}

#[test]
fn page_needs_a_current_list_grant_and_a_changed_revision_is_reread() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "job").job_id;
    let confirm = |keys: Vec<execution_reads::PageKey>| {
        f.store.request(|reply| {
            Command::ExecutionRead(execution_reads::ReadCommand::ConfirmPage(
                auth.clone(),
                keys,
                reply,
            ))
        })
    };
    // A revision committed between capture and return makes the capture stale.
    let raw = raw_page(&f, &auth, 20);
    dispatch(&f, &job);
    assert!(!confirm(raw.keys()).unwrap());
    // The public page rereads and returns the fresh revision.
    let fresh = page(&f, &auth, None, None).unwrap();
    assert_eq!(fresh.items[0].state, ExecutionJobState::Running);
    assert_eq!(fresh.items[0].snapshot_revision, 2);
    // Revocation between capture and return wins.
    let raw = raw_page(&f, &auth, 20);
    f.store.revoke_self(auth.clone()).unwrap();
    assert!(matches!(confirm(raw.keys()), Err(CoreError::Unauthorized)));
    assert_eq!(
        page(&f, &auth, None, None).unwrap_err().code,
        ErrorCode::Unauthorized
    );
}

#[test]
fn legacy_list_and_show_fail_explicitly_once_a_row_is_not_queued() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let first = accept(&f, "first").job_id;
    let second = accept(&f, "second").job_id;
    let list = |limit: Option<u8>, cursor: Option<String>| {
        f.store.list_jobs(auth.clone(), JobsQuery { limit, cursor })
    };
    let queued_only = list(None, None).unwrap();
    assert_eq!(queued_only.items.len(), 2);
    for (job, label) in [(&second, "running"), (&second, "cancel_requested")] {
        if label == "running" {
            dispatch(&f, job);
        } else {
            f.store
                .cancel_execution_job(auth.clone(), job.clone())
                .unwrap();
        }
        // Never dropped and never shown as queued: the unnegotiated read fails.
        assert_eq!(
            list(None, None).unwrap_err().code,
            ErrorCode::IncompatibleContract,
            "{label}"
        );
        assert_eq!(
            f.store
                .show_job(auth.clone(), job.clone())
                .unwrap_err()
                .code,
            ErrorCode::IncompatibleContract,
            "{label}"
        );
        // Queued-only reads keep their old form.
        let head = list(Some(1), None).unwrap();
        assert_eq!(head.items[0].job_id, first);
        assert_eq!(head.items[0].state, JobState::Queued);
        assert_eq!(
            list(Some(1), head.next_cursor).unwrap_err().code,
            ErrorCode::IncompatibleContract
        );
        f.store.show_job(auth.clone(), first.clone()).unwrap();
    }
    // A terminal row fails the same way.
    let canceled = canceled_source(&f, &auth, "terminal");
    assert_eq!(
        f.store.show_job(auth.clone(), canceled).unwrap_err().code,
        ErrorCode::IncompatibleContract
    );
}
