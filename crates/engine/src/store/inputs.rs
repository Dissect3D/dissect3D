//! Actor-owned input pins, expiry claims and confirmed cleanup state.

use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputCleanupKind {
    Reservation { reservation_id: String },
    Captured,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InputCleanupClaim {
    pub(crate) input_id: InputId,
    pub(crate) kind: InputCleanupKind,
}

/// Temporary actor-issued leases prevent file cleanup while validation reads.
/// Their count is process-local; a restart has no surviving validation work.
pub(crate) struct InputPins {
    counters: Vec<(InputId, Arc<AtomicUsize>)>,
}

/// Actor-authorized immutable input identities held alive by temporary pins.
pub(crate) struct PinnedInputSet {
    pub(crate) identities: Vec<InputIdentity>,
    _pins: InputPins,
}

pub(super) fn input_file_known(
    connection: &Connection,
    input_id: &InputId,
) -> Result<bool, CoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM input_upload_reservations WHERE input_id=?1
                UNION ALL
                SELECT 1 FROM captured_inputs WHERE input_id=?1
             )",
            [input_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

impl Drop for InputPins {
    fn drop(&mut self) {
        for (_, counter) in &self.counters {
            let previous = counter.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "input pin count underflow");
        }
    }
}

pub(super) type ActiveUploads = HashMap<String, Arc<()>>;
pub(super) type InputPinCounts = HashMap<String, Arc<AtomicUsize>>;

#[derive(Default)]
pub(super) struct CleanupCursor(Option<(i64, String)>);

pub(super) fn pin_inputs(
    connection: &mut Connection,
    context: AuthContext,
    input_ids: Vec<InputId>,
    pin_counts: &mut InputPinCounts,
) -> Result<PinnedInputSet, CoreError> {
    if input_ids.is_empty() {
        return Err(CoreError::Conflict);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    require_active_grant(&transaction, &context, "jobs.submit")?;
    let now = observe_wall_time_at(&transaction, now_ms()?)?;
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for input_id in input_ids {
        if !seen.insert(input_id.as_str().to_owned()) {
            continue;
        }
        let record: Option<(String, i64, String, String, i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT client_id,expires_at_ms,cleanup_state,media_type,byte_length,sha256
                 FROM captured_inputs
                 WHERE input_id=?1",
                [input_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| CoreError::StoreUnavailable)?;
        let Some((client_id, expires_at, state, media_type, byte_length, sha256)) = record else {
            return Err(CoreError::NotFound);
        };
        let retained: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM job_inputs WHERE input_id=?1)",
                [input_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        if client_id != context.client_id.as_str()
            || (expires_at <= now && !retained)
            || state != "complete"
        {
            return Err(CoreError::NotFound);
        }
        let digest: [u8; 32] = sha256.try_into().map_err(|_| CoreError::InvalidStore)?;
        unique.push((
            input_id.clone(),
            InputIdentity {
                input_id: input_id.clone(),
                media_type,
                byte_length: u64::try_from(byte_length).map_err(|_| CoreError::InvalidStore)?,
                sha256: ContentDigest::parse(digest_hex(&digest))
                    .map_err(|_| CoreError::InvalidStore)?,
            },
        ));
    }

    let mut pins = InputPins {
        counters: Vec::with_capacity(unique.len()),
    };
    let mut identities = Vec::with_capacity(unique.len());
    for (input_id, identity) in unique {
        let counter = pin_counts
            .entry(input_id.as_str().to_owned())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CoreError::Busy)?;
        pins.counters.push((input_id, counter));
        identities.push(identity);
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(PinnedInputSet {
        identities,
        _pins: pins,
    })
}

pub(super) fn claim_input_cleanup(
    connection: &mut Connection,
    active_uploads: &mut ActiveUploads,
    pin_counts: &mut InputPinCounts,
    cursor: &mut CleanupCursor,
    requested_time_ms: Option<i64>,
) -> Result<Vec<InputCleanupClaim>, CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let requested_time_ms = match requested_time_ms {
        Some(value) => value,
        None => now_ms()?,
    };
    let now = observe_wall_time_at(&transaction, requested_time_ms)?;
    let mut claims = Vec::with_capacity(MAX_CLEANUP_BATCH);
    let mut file_entries = 0usize;

    let reservations = {
        let mut statement = transaction
            .prepare(
                "SELECT reservation_id,input_id FROM input_upload_reservations
                 ORDER BY created_at_ms,reservation_id LIMIT ?1",
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        let rows = statement
            .query_map([MAX_CLEANUP_BATCH as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| CoreError::StoreUnavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoreError::StoreUnavailable)?
    };
    for (reservation_id, input_id) in reservations {
        if file_entries + 2 > MAX_CLEANUP_BATCH {
            break;
        }
        if active_uploads
            .get(&reservation_id)
            .is_some_and(|lease| Arc::strong_count(lease) > 1)
        {
            continue;
        }
        active_uploads.remove(&reservation_id);
        let input_id = InputId::parse(input_id).map_err(|_| CoreError::InvalidStore)?;
        claims.push(InputCleanupClaim {
            input_id,
            kind: InputCleanupKind::Reservation { reservation_id },
        });
        file_entries += 2;
    }

    if file_entries < MAX_CLEANUP_BATCH {
        let expired = {
            let mut statement = transaction
                .prepare(
                    "SELECT input_id,cleanup_state,expires_at_ms FROM captured_inputs
                     WHERE NOT EXISTS (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)
                       AND (cleanup_state='deleting' OR expires_at_ms<=?1)
                       AND (?2 IS NULL OR (expires_at_ms,input_id)>(?2,?3))
                     ORDER BY expires_at_ms,input_id LIMIT ?4",
                )
                .map_err(|_| CoreError::StoreUnavailable)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        now,
                        cursor.0.as_ref().map(|value| value.0),
                        cursor.0.as_ref().map(|value| value.1.as_str()),
                        MAX_CLEANUP_BATCH as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(|_| CoreError::StoreUnavailable)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| CoreError::StoreUnavailable)?
        };
        let selected = expired.len();
        let mut examined = 0;
        for (raw_id, state, expires_at_ms) in expired {
            if file_entries == MAX_CLEANUP_BATCH {
                break;
            }
            examined += 1;
            cursor.0 = Some((expires_at_ms, raw_id.clone()));
            let input_id = InputId::parse(raw_id).map_err(|_| CoreError::InvalidStore)?;
            if pin_counts
                .get(input_id.as_str())
                .is_some_and(|count| count.load(Ordering::Acquire) != 0)
            {
                continue;
            }
            if state == "complete" {
                let changed = transaction
                    .execute(
                        "UPDATE captured_inputs SET cleanup_state='deleting'
                         WHERE input_id=?1 AND cleanup_state='complete' AND expires_at_ms<=?2",
                        rusqlite::params![input_id.as_str(), now],
                    )
                    .map_err(|_| CoreError::StoreUnavailable)?;
                if changed != 1 {
                    continue;
                }
            } else if state != "deleting" {
                return Err(CoreError::InvalidStore);
            }
            claims.push(InputCleanupClaim {
                input_id,
                kind: InputCleanupKind::Captured,
            });
            file_entries += 1;
        }
        if examined == selected && selected < MAX_CLEANUP_BATCH {
            cursor.0 = None;
        }
    }
    pin_counts.retain(|_, count| count.load(Ordering::Acquire) != 0);
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(claims)
}

pub(super) fn confirm_input_cleanup(
    connection: &mut Connection,
    claim: InputCleanupClaim,
) -> Result<(), CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    match claim.kind {
        InputCleanupKind::Reservation { reservation_id } => {
            transaction
                .execute(
                    "DELETE FROM input_upload_reservations
                     WHERE reservation_id=?1 AND input_id=?2",
                    rusqlite::params![reservation_id, claim.input_id.as_str()],
                )
                .map_err(|_| CoreError::StoreUnavailable)?;
        }
        InputCleanupKind::Captured => {
            transaction
                .execute(
                    "DELETE FROM captured_inputs
                     WHERE input_id=?1 AND cleanup_state='deleting'",
                    [claim.input_id.as_str()],
                )
                .map_err(|_| CoreError::StoreUnavailable)?;
        }
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn observe_wall_time_at(
    transaction: &Transaction<'_>,
    requested_time_ms: i64,
) -> Result<i64, CoreError> {
    if requested_time_ms < 0 {
        return Err(CoreError::StoreUnavailable);
    }
    let last_observed: i64 = transaction
        .query_row(
            "SELECT last_observed_ms FROM engine_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let observed = requested_time_ms.max(last_observed);
    transaction
        .execute(
            "UPDATE engine_clock SET last_observed_ms=?1 WHERE singleton=1",
            [observed],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(observed)
}

pub(super) fn reserve_upload(
    connection: &mut Connection,
    context: AuthContext,
    declared_length: u64,
    media_type: &str,
    available_space_bytes: u64,
) -> Result<UploadReservation, CoreError> {
    if !(1..=MAX_INPUT_BYTES).contains(&declared_length) || media_type != "application/octet-stream"
    {
        return Err(CoreError::Conflict);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    require_active_grant(&transaction, &context, "inputs.create")?;
    let open_uploads: i64 = transaction
        .query_row(
            "SELECT count(*) FROM input_upload_reservations",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if open_uploads >= MAX_UPLOADS {
        return Err(CoreError::CapacityExceeded("upload_concurrency_max"));
    }
    let total_inputs: i64 = transaction
        .query_row("SELECT count(*) FROM captured_inputs WHERE NOT EXISTS (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if total_inputs.saturating_add(open_uploads) >= MAX_INPUT_ROWS {
        return Err(CoreError::CapacityExceeded("staged_input_records_max"));
    }
    let captured_bytes: i64 = transaction
        .query_row(
            "SELECT coalesce(sum(byte_length),0) FROM captured_inputs WHERE NOT EXISTS (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let reserved_bytes: i64 = transaction
        .query_row(
            "SELECT coalesce(sum(declared_length),0) FROM input_upload_reservations",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let current_staging = u64::try_from(captured_bytes)
        .ok()
        .and_then(|captured| {
            u64::try_from(reserved_bytes)
                .ok()
                .and_then(|reserved| captured.checked_add(reserved))
        })
        .ok_or(CoreError::InvalidStore)?;
    if current_staging
        .checked_add(declared_length)
        .is_none_or(|total| total > MAX_STAGING_BYTES)
    {
        return Err(CoreError::CapacityExceeded("staging_reserved_bytes_max"));
    }
    let reserved_metadata = u64::try_from(open_uploads)
        .ok()
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_mul(UPLOAD_METADATA_RESERVE_BYTES))
        .ok_or(CoreError::InvalidStore)?;
    // Other uploads may not have written their reserved bytes yet. A free-space
    // probe alone cannot promise those same bytes to another reservation.
    let required_free = u64::try_from(reserved_bytes)
        .map_err(|_| CoreError::InvalidStore)?
        .checked_add(declared_length)
        .and_then(|total| total.checked_add(reserved_metadata))
        .and_then(|total| total.checked_add(STORAGE_FREE_RESERVE_BYTES))
        .ok_or(CoreError::InvalidStore)?;
    if available_space_bytes < required_free {
        return Err(CoreError::CapacityExceeded("storage_free_reserve_bytes"));
    }

    let reservation_id = random_id("upr_")?;
    let input_id = InputId::parse(random_id("inp_")?).map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT INTO input_upload_reservations
             (reservation_id,input_id,client_id,declared_length,media_type,created_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                reservation_id,
                input_id.as_str(),
                context.client_id.as_str(),
                i64::try_from(declared_length).map_err(|_| CoreError::LimitReached)?,
                media_type,
                now_ms()?
            ],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(UploadReservation {
        reservation_id,
        input_id,
        declared_length,
        media_type: media_type.to_owned(),
        lease: Arc::new(()),
    })
}

pub(super) fn complete_upload(
    connection: &mut Connection,
    context: AuthContext,
    reservation: UploadReservation,
    input: DurableInput,
) -> Result<InputReceipt, CoreError> {
    if input.file.length() != reservation.declared_length {
        return Err(CoreError::Platform(PlatformError::InvalidFile));
    }
    let expected_path =
        RelativePath::parse(format!("inputs/data/{}.bin", reservation.input_id.as_str()))
            .map_err(CoreError::Platform)?;
    if input.file.relative_path() != &expected_path {
        return Err(CoreError::Platform(PlatformError::InvalidFile));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    require_active_grant(&transaction, &context, "inputs.create")?;
    let record: Option<(String, String, i64, String)> = transaction
        .query_row(
            "SELECT input_id,client_id,declared_length,media_type
             FROM input_upload_reservations WHERE reservation_id=?1",
            [&reservation.reservation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let Some((input_id, client_id, declared_length, media_type)) = record else {
        return Err(CoreError::NotFound);
    };
    if input_id != reservation.input_id.as_str()
        || client_id != context.client_id.as_str()
        || u64::try_from(declared_length).ok() != Some(reservation.declared_length)
        || media_type != reservation.media_type
    {
        return Err(CoreError::Conflict);
    }
    let completed_at_ms = inputs::observe_wall_time_at(&transaction, now_ms()?)?;
    let expires_at_ms = completed_at_ms
        .checked_add(UPLOAD_TTL_MS)
        .ok_or(CoreError::StoreUnavailable)?;
    let digest = digest_hex(&input.sha256);
    let receipt = InputReceipt {
        api_version: "1.0".to_owned(),
        identity: InputIdentity {
            input_id: reservation.input_id.clone(),
            media_type: reservation.media_type,
            byte_length: reservation.declared_length,
            sha256: ContentDigest::parse(digest).map_err(|_| CoreError::StoreUnavailable)?,
        },
        complete: true,
        completed_at_ms: TimestampMs::new(
            u64::try_from(completed_at_ms).map_err(|_| CoreError::StoreUnavailable)?,
        )
        .map_err(|_| CoreError::StoreUnavailable)?,
        expires_at_ms: TimestampMs::new(
            u64::try_from(expires_at_ms).map_err(|_| CoreError::StoreUnavailable)?,
        )
        .map_err(|_| CoreError::StoreUnavailable)?,
    };
    transaction
        .execute(
            "INSERT INTO captured_inputs
             (input_id,client_id,media_type,byte_length,sha256,completed_at_ms,expires_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                receipt.identity.input_id.as_str(),
                context.client_id.as_str(),
                receipt.identity.media_type,
                i64::try_from(receipt.identity.byte_length).map_err(|_| CoreError::InvalidStore)?,
                input.sha256.as_slice(),
                completed_at_ms,
                expires_at_ms
            ],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let removed = transaction
        .execute(
            "DELETE FROM input_upload_reservations WHERE reservation_id=?1",
            [&reservation.reservation_id],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if removed != 1 {
        return Err(CoreError::Conflict);
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(receipt)
}

pub(super) fn abandon_upload(
    connection: &mut Connection,
    reservation_id: &str,
) -> Result<(), CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "DELETE FROM input_upload_reservations WHERE reservation_id=?1",
            [reservation_id],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)
}
