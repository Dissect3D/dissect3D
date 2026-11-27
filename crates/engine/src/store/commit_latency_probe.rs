//! Opt-in raw SQLite WAL `synchronous=FULL` commit-latency probe. It measures the
//! storage stack only, not Store admission, and prints JSON without asserting time.
#![expect(
    clippy::disallowed_methods,
    reason = "Opt-in probe measures raw SQLite commit latency on a scratch file, so it must \
              bypass the store; production opens only via store/schema.rs"
)]
use rusqlite::Connection;
use std::time::{Duration, Instant};

#[test]
#[ignore = "opt-in storage latency measurement"]
fn measure_raw_wal_full_commit_latency() {
    const COMMITS: usize = 500;
    let parent = std::env::var_os("DISSECT3D_MEASURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = tempfile::tempdir_in(&parent).unwrap();
    let connection = Connection::open(dir.path().join("probe.sqlite3")).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap();
    assert!(mode.eq_ignore_ascii_case("wal"));
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             CREATE TABLE clock(singleton INTEGER PRIMARY KEY, value INTEGER NOT NULL);
             INSERT INTO clock VALUES(1, 0);",
        )
        .unwrap();
    let mut samples: Vec<Duration> = Vec::with_capacity(COMMITS);
    for value in 0..COMMITS as i64 {
        let started = Instant::now();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        connection
            .execute("UPDATE clock SET value=?1 WHERE singleton=1", [value])
            .unwrap();
        connection.execute_batch("COMMIT").unwrap();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let at =
        |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize].as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({
            "probe": "raw-sqlite-wal-full-commit",
            "os": std::env::consts::OS,
            "parent_dir": parent.display().to_string(),
            "commits": COMMITS,
            "p50_ms": at(0.50),
            "p90_ms": at(0.90),
            "p99_ms": at(0.99),
            "max_ms": at(1.0),
        })
    );
}
