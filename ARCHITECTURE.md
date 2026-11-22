# Architecture

This document is a map of the Dissect3D Rust workspace: where things are, which
module may depend on which, and where tests and fixtures live. It describes the
code as it is today and marks known departures from the intended layering as
TODOs. It does not add requirements. The accepted design constraints are in the
"Architecture to preserve" section of [AGENTS.md](AGENTS.md#architecture-to-preserve),
and project status is in [README.md](README.md).

Everything here can be checked against the source. If this map and the code
disagree, the code is right and this file should be fixed.

## Bird's-eye view

One engine process runs per OS user. It owns support resolution, durable jobs,
resource reservations and (eventually) published results. Clients such as the
`dissect3d` CLI talk to it over an authenticated loopback HTTPS API. They never
open its database. Workers will be supervised child processes that speak a
private protocol. Inside the engine, a request flows like this:

```text
client ──HTTPS/JSON──▶ http (decode, authenticate, map errors)
                          │
                          ▼
              services: submission, inputs, jobs, execution, publication, support
                          │
                          ▼
              store (one SQL actor thread owning the SQLite connection)
                          │
                          ▼
              SQLite metadata  +  engine-owned files via dissect3d-platform
```

HTTP handlers contain no SQL. The CLI contains no SQL and no engine file access.

## Crates

The workspace has five crates under `crates/`. Arrows show allowed project
dependencies. Nothing depends on `dissect3d-engine` or `dissect3d-cli`.

```text
dissect3d-cli ──▶ dissect3d-connection ──▶ dissect3d-api
      │                    │
      │                    └──────────────▶ dissect3d-platform
      ├──▶ dissect3d-api (feature "client")
      └──▶ dissect3d-platform

dissect3d-engine ──▶ dissect3d-api, dissect3d-platform
                 ──▶ dissect3d-connection (only with feature "test-support")
```

| Crate | Path | Role |
| --- | --- | --- |
| `dissect3d-api` | `crates/api/` | Shared wire types, public error codes and strict JSON decoding. The optional `client` feature adds the HTTP client (`Client`) that the CLI and tests use. It has no project dependencies. |
| `dissect3d-platform` | `crates/platform/` | Operating-system boundary: owned root and files, durable writes, authority lease, private bootstrap IPC, process lifetime and worker containment. All `unsafe` and native flag handling lives here, in per-OS modules (`windows.rs`, `worker/linux.rs`, `worker/macos.rs`, ...). Also builds the `dissect3d-worker-guardian` helper binary. It has no project dependencies. |
| `dissect3d-connection` | `crates/connection/` | Engine discovery validation, process identity checks and native readiness probes shared by the CLI and engine test hosts. |
| `dissect3d-engine` | `crates/engine/` | The engine library and the `dissect3d-engine` binary: access control, HTTP service, durable store, submission, execution supervision and result publication. |
| `dissect3d-cli` | `crates/cli/` | The `dissect3d` command-line client: argument parsing, profiles and configuration, connection setup and output rendering. |

Feature flags:

| Flag | Crate | Meaning |
| --- | --- | --- |
| `client` | `dissect3d-api` | Compiles the HTTP client and its transport dependencies. |
| `test-support` | `dissect3d-engine` | Compiles the explicit test hosts and fixtures (`submission_fixture`, `execution_fixture`, the `examples/` binaries). Never part of a normal engine build. |
| `native-test-hooks` | `dissect3d-platform` | Exposes the `native_test_hooks` fault-injection seam. Absent from normal builds. |

Both `main.rs` files only set up the process and call a library entry point.
Behaviour lives in named library modules.

## Engine modules

All paths are relative to `crates/engine/src/`. A module `foo` is `foo.rs`, and
its children live in `foo/`. Several modules are compiled on Unix only today
(`inputs`, `jobs`, most of `submission` and the input/job parts of `store`).

| Module | Responsibility |
| --- | --- |
| `startup` | Engine entry: root and authority, metadata recovery, listeners, ready descriptor. Also the `test-support` test-engine entry points. |
| `bootstrap` | Private same-owner enrollment over native IPC, before any HTTP credential exists. |
| `credentials` | Credential and grant records passed into the store actor (`AuthContext`, `VerifiedEnrollment`, grant policies). Raw tokens never appear here. |
| `http` | Loopback listener, TLS, bounded HTTP/1 parsing, Host/Origin policy, authentication and error mapping. Feature routes are in `http/{access,discovery,inputs,jobs}.rs`; `http/framing.rs` holds shared response framing. |
| `tls` | Installation certificate authority and the per-run loopback HTTPS identity. |
| `support` | The support catalog: declaration decoding and validation (`support/declarations.rs`), resolution, compatibility, observations and paginated discovery reads. |
| `submission` | Bounded admission, request equivalence, durable submission orchestration and the bounded OBJ fixture validator. |
| `inputs` | Input upload capture and publication, budgets, policy limits and conservative recovery. |
| `jobs` | Private job inspection. Polling reads retained snapshots only. |
| `execution` | Worker supervision: attempt files, launcher, session legality, progress and the supervisor. Dispatch is inactive. |
| `worker_protocol` | The private engine–worker frame and message codec. |
| `publication` | Validation of captured result candidates, private durable storage and publication policy limits. No route or dispatch uses it yet. |
| `store` | The `Store` handle, the SQL actor thread, schema and migrations, and all durable records. `store.rs` is the handle and actor; `store/` holds one file per record family (`submission`, `jobs`, `retry`, `execution`, `finalize`, `cleanup`, `results`, `inputs`, ...). |
| `diagnostics` | Bounded startup diagnostics with fixed codes. No paths, request data or secrets. |
| `policy` | `CorePolicy`, the engine-wide bounds. |
| `submission_fixture`, `execution_fixture` | `test-support` only. Explicit prepared test support and a fixture worker, used by the `examples/` test hosts. |

Public surface: `lib.rs` re-exports a small set of names (`Store`, `CoreError`,
`StoreIdentity`, `HttpServer`, `CorePolicy`, `AuthContext`, `run_engine`, and the
`test-support` entry points). Integration tests import these paths, so keep
them stable when you move code. Everything else is crate-private.

## Dependency rules

These are the intended directions inside the engine. "A → B" means code in A
may use items from B.

```text
startup, bootstrap
      │
      ▼
http ──▶ services (submission, inputs, jobs, execution, publication, support)
                              │
                              ▼
                            store
                              │
                              ▼
     shared engine types (credentials, policy, policy constants, record types)
                              │
                              ▼
              dissect3d-api, dissect3d-platform, SQLite
```

- `http` may use services and `store`. Services must not use `http`.
- Services may use `store`. `store` must not use services; it depends only on
  shared engine types, `dissect3d-api`, `dissect3d-platform` and `rusqlite`.
- `worker_protocol` is a leaf codec. `execution` may use it.
- `submission_fixture` and `execution_fixture` may use anything. Production
  modules may refer to them only behind `#[cfg(feature = "test-support")]`.
- Tests (`*_tests.rs`, `*_regressions.rs`, inline `mod tests`) may reach across
  modules to drive real paths, for example by starting an `HttpServer`.
- Native and per-OS code belongs in `dissect3d-platform`, not in the engine.

### Known violations (TODO)

Measured from production code (tests excluded) by grepping `crate::<module>`:

- TODO: `store` imports service types. These are `SubmissionError`,
  `AdmissionCandidate`, `PreparedAdmission`, `SubmittedJobRequest` and
  `VerifiedInputMap` from `submission`; `AttemptEnd`, `StopIntent`,
  `AttemptCleanup` and `ObservationUpdate` from `execution`; the limit constants
  in `inputs::policy` and `publication::policy`; and test hooks from
  `submission::test_support`. These should move into a layer below `store`.
- TODO: module cycles through `store`: `store ↔ submission`, `store ↔ execution`,
  `store ↔ inputs` and `store ↔ publication`.
- TODO: service-to-service cycles: `submission ↔ inputs`, `submission ↔ jobs`
  and `submission ↔ submission_fixture`.
- `submission → http` appears only in tests, which start a real `HttpServer`.
  That is allowed.

## Tests and fixtures

| Kind | Location | Convention |
| --- | --- | --- |
| Unit tests | Next to the code | Put substantial tests in a sibling `<name>_tests.rs` included from the parent with `#[cfg(test)] #[path = "<name>_tests.rs"] mod tests;` (or as a named child module). Keep inline `mod tests` blocks small. Including a file as `mod tests` keeps the test path (`module::tests::name`) stable when it moves out of the parent file. |
| Defect regressions | Next to the code | A separate `<topic>_regressions.rs` per fixed defect group, added without rewriting older tests. |
| Integration tests | `crates/<crate>/tests/*.rs` | One Cargo test target per file. Verification catalogues refer to these target names, so do not rename them or move them between crates. |
| Protected tests | `crates/*/tests/` | Some integration test files are byte-protected (listed in [.gitattributes](.gitattributes)). Do not edit them. Add new tests in new files. |
| Data fixtures | `crates/<crate>/tests/fixtures/` | Each folder has a `PROVENANCE.md`. Bytes are hashed or embedded, so line endings are fixed by `.gitattributes`. |
| Test hosts | `crates/engine/examples/` | `discovery_test_host`, `selection_test_host`, `submission_test_host`, `submission_fixture_tool`, `execution_fixture_worker` and `execution_fixture_tool`. They need `--features test-support`. |
| Fixture modules | `crates/engine/src/submission_fixture.rs`, `crates/engine/src/execution_fixture.rs` | Prepared CPU test support and a fixture worker. `test-support` only. |
| Native fault seams | `crates/platform/src/native_test_hooks.rs` | Behind `native-test-hooks`. |

Many integration tests launch real engine and CLI binaries. See
[Getting started today](README.md#getting-started-today) for the environment
variables and the Windows independent-host runner.

## Naming and file size

- Name modules by responsibility (`access`, `admission`, `shutdown`), not
  `utils`, `helpers` or `common`. Use the project vocabulary (support
  definition, task, runtime profile, attempt, artifact) and do not invent a
  second name for an existing fact.
- A parent module is `foo.rs`, with children in `foo/`. Do not use `mod.rs`.
- Soft cap: about 800 production lines per file, not counting tests. Above that,
  split by responsibility. No file needs to be split just to reach a number.
  Some files are far over this today: `store.rs`, `submission/admission.rs`,
  `support/declarations.rs`, `cli/src/commands.rs` and `api/src/client.rs`.
- Default to private. Use `pub(super)` before `pub(crate)`, and `pub(crate)`
  before `pub`. Items reach other crates only through re-exports in `lib.rs`.
- Keep wire types (`dissect3d-api`), SQLite rows (`store`) and OS handles
  (`dissect3d-platform`) separate. Do not create a catch-all `types` module.
- Keep `#[cfg(unix)]`, `#[cfg(windows)]` and feature gates on the item they
  protect. Do not use a module move to change where a gate applies.
- Line endings differ between source files. Keep each file's existing style.

## Adding a feature module

1. Pick the layer. Wire types go in `dissect3d-api`. OS behaviour goes in
   `dissect3d-platform`. Engine logic goes in a named engine module.
2. Create `crates/engine/src/<feature>.rs` and declare it in `lib.rs`. Keep it
   private, and add a `lib.rs` re-export only if another crate needs it.
3. Put durable records in a new `store/<feature>.rs` with its own `Command`
   variants handled by the store actor. Store code must not import the feature
   module. Shared record types go in the layer below `store`.
4. Add HTTP routes in `http/<feature>.rs`. Handlers decode, authenticate, call
   the service and map errors.
5. Add unit tests in `<feature>_tests.rs`, and integration tests as a new file
   in `crates/engine/tests/`.
6. Update this map if you add a module, a crate or a dependency direction.
