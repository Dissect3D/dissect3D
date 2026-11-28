# Dissect3D

**Local AI for 3D generation and part processing.**

Dissect3D is an open-source project building a shared local engine for turning
images into 3D assets and processing existing meshes into parts. The goal is to
prepare models once, run them on your own hardware, and use the same jobs and
results from a terminal, a desktop application, Blender, or Unity.

**Status: bounded Rust core service and CLI implemented; acceptance incomplete.**
Available operations include local configuration, engine start/status/info/stop,
auth setup/status/revoke, and read-only model/runtime/task support discovery.
`auth setup --submission-access` opts a new empty CLI profile into four queued-
submission grants; it does not upgrade an existing profile. Bounded durable
queued submission, exact-request recovery and creator-private list/show are
implemented. The normal production catalog is empty, so it supplies no prepared
support for new jobs. Explicitly prepared CPU test support exercises those paths
in a separate maintainer host.
Discovery describes declared support, not installed or validated inference.
Production model preparation, inference, production worker execution and result publication,
graphical clients, plugins, and installers remain unimplemented.

Worker execution and result publication exist as engine code that only an
explicit maintainer test host runs. The maintainers' feature records hold exact
contents, recorded evidence and open gates; they are not needed to build or
verify the code. Recorded tests and explicit test support do not establish
accepted platform or model support.

- **Normal engine.** Dispatch is inactive: no worker runs and nothing is
  published. On Unix it serves read-only committed-result list/show, manifest,
  artifact and storage reads over an empty result store, and the CLI has
  `results` and `storage` commands for them.
- **Unix test-support execution host.** A FIFO scheduler and controller launch a
  controlled CPU fixture worker under native process-tree containment, supervise
  it through a bounded private protocol, confirm cleanup, then validate and
  publish its output. Cancellation, linked retry, shutdown and restart
  reconciliation are implemented there. The store uses feature schema v8.
- **Windows.** Native worker containment and durable file primitives exist and
  are tested, but input capture, submission, job, execution and publication
  services are not composed in the Windows engine until ordinary-user namespace
  guarantees and Windows parity work are complete.
- **macOS.** Worker trees that never fork reach confirmed cleanup in native
  tests; a tree that forks is reported as unconfirmed until forked-descendant
  closure is implemented.

- **CLI execution and controlled-spine proof (`CJ-G1`).** The CLI implements
  `auth setup --execution-access`, `auth authorize --execution-access`,
  foreground `run` (with `--output DIR`, `--execution-timeout-ms`,
  `--observe-timeout-ms`, two-stage Ctrl+C, and inert Esc),
  `jobs watch|wait|cancel|retry`, and execution/retry `jobs recover`. Against
  the explicit Unix `test-support` host (`execution_test_host` provisioned via
  `execution_fixture_tool enroll-and-export`), the first complete controlled
  `test.mesh-copy@fixture-r2` job flow (foreground run, supervised worker,
  confirmed cleanup, validation/publication, authenticated manifest/artifact
  retrieval, no-overwrite download, and restart retention) is verified on
  Darwin arm64. Native Windows execution parity (`PH-2-PRE`), bare-metal Linux
  runtime acceptance, macOS forked-descendant closure, and real-model/GPU
  inference remain open.

[Why Dissect3D?](#why-dissect3d) · [Workflows](#intended-workflows) ·
[Models](#target-models) · [Architecture](#architecture) ·
[Platforms](#platform-direction) · [Contributing](#contributing)

## Why Dissect3D?

Using several 3D models means working with different inputs, dependencies,
hardware constraints, and output conventions. Moving between a research script,
a terminal, and a creative application adds another layer of setup and state to
manage.

Dissect3D aims to make that work consistent:

- **One model installation across tools.** Clients share the engine's model
  inventory, prepared runtimes, jobs, and results.
- **Local execution after preparation.** Declared local workflows run offline
  once their dependencies and assets are ready. Downloads are explicit, and
  inputs are never silently sent to an external inference or preprocessing service.
- **Model-specific capabilities.** Each integration describes its actual tasks,
  required inputs, options, and outputs. Image-to-3D generation, mesh segmentation,
  and part completion retain their different requirements.
- **An engine that owns the work.** Accepted jobs have persistent identities and
  outcomes, so closing a client does not lose the work or its history.
- **Results with context.** Validated geometry comes with part structure,
  transforms, provenance, and explicit limitations for preview or import.

The local-service experience is inspired by [Ollama](https://github.com/ollama/ollama).
Dissect3D applies that approach to 3D workloads with managed inference environments
and durable jobs. API compatibility with Ollama is not part of the current scope.

## Intended workflows

### Generate 3D parts from an image

Choose a model and task, inspect its required conditioning, and explicitly prepare
a compatible runtime. Supply an image with the required mask or part count, submit
a job, and retrieve the generated part meshes and assembly information. A future
Desktop client would preview the result; Blender and Unity plugins would import
supported artifacts into a scene or project.

### Process an existing mesh

Supply a mesh to a declared part-segmentation or part-completion task. Segmentation
identifies constituent regions; completion generates complete part geometry from
the model's required conditioning. These are separate capabilities, even when an
upstream pipeline combines them.

### Automate and integrate

Use the CLI or public local API to inspect readiness, submit work, monitor or
cancel a job, and retrieve its results. An accepted job stays owned by the engine
when a client disconnects. After an engine restart, interrupted execution is
reported accurately; retry is explicit.

| Planned client | Role |
| --- | --- |
| CLI | Model and runtime operations, task discovery, job submission and control, result retrieval, and scripting |
| Desktop | Model management, job monitoring, and 3D preview |
| Blender plugin | Submit image or mesh tasks and import supported results into Blender |
| Unity plugin | Submit tasks and import supported results into Unity |

Desktop's initial scope is preview. Editing and further model-driven modifications
need their own requirements.

## Target models

These are integration targets, with **no Dissect3D adapters or validated support
profiles yet**. Their input requirements are part of the integration design.

| Target | Intended workflow | Upstream input distinction |
| --- | --- | --- |
| [OmniPart](https://github.com/HKU-MMLab/OmniPart) | Image to structured 3D parts | The documented inference path requires an image and an EXR part mask |
| [PartCrafter](https://github.com/wgsxm/PartCrafter) | Image to structured 3D parts | The local generation path uses an image and a part count |
| [Hunyuan3D-Part](https://github.com/Tencent-Hunyuan/Hunyuan3D-Part) | Existing mesh to segmented or completed parts | P3-SAM performs mesh part segmentation; X-Part generates complete parts from the pipeline's conditioning |

The Hunyuan target is mesh-input part processing. Exact releases and exposed
subtasks remain to be selected; the released X-Part is described upstream as a
light version. Optional external assistance in upstream projects must remain
explicit and separate from a declared local workflow.

Model descriptions were checked against the linked upstream READMEs on
2026-10-26. Those default branches can change. Upstream documentation establishes
input and pipeline distinctions, not Dissect3D compatibility or validation.

## Architecture

```text
CLI          Desktop          Blender plugin          Unity plugin
 |              |                   |                      |
 +--------------+-------------------+----------------------+
                            |
                 Shared local API (HTTP/JSON)
                   Polling + resumable events
                            |
                  Dissect3D Engine (Rust)
       Models | Runtimes | Jobs | Resources | Results
                            |
                  Supervised worker processes
                            |
              Model adapter + isolated runtime
                            |
                  Upstream model pipeline
```

One engine per operating-system user owns the shared state. Clients present
capabilities and results through the public API. Model execution runs in separate
supervised processes with compatible managed dependencies, keeping Python and
native inference libraries outside Blender and Unity.

| Component | Responsibility |
| --- | --- |
| Engine | Resolve model support, prepare assets and runtimes, check readiness, persist jobs, schedule resources, supervise workers, and publish validated results |
| Model adapter | Translate declared task inputs into an upstream pipeline while preserving its required preprocessing, inference, and postprocessing |
| Runtime profile | Identify the interpreter, dependencies, and platform constraints required for an integration |
| Result artifacts | Store geometry and a versioned manifest describing files, parts, transforms, materials, provenance, and validation findings |
| Clients | Handle user interaction, submission, monitoring, retrieval, preview, or host import |

Selected engine foundations are **Rust**, **HTTP/JSON** with polling and resumable
**Server-Sent Events (SSE)**, and **SQLite** for local metadata. Large inputs,
weights, and meshes live outside the database. Public access is restricted to
loopback with per-client authorization. The bounded core implements service control, authentication, and SQLite metadata;
broader execution and resumable events remain planned.

Client languages and frameworks, runtime provisioning tools, installer technology,
broader API schemas, and future component layouts remain open.

For the current source layout (crates, engine modules, allowed dependency
directions, and where tests and fixtures live), see [ARCHITECTURE.md](ARCHITECTURE.md).

## Platform direction

Core application support and model inference support have separate validation
requirements.

| Area | Target | Current evidence |
| --- | --- | --- |
| CLI and engine installation and operation | Bounded Windows, macOS, and Linux targets, independently of Desktop | Bounded core evidence; full acceptance pending |
| Initial model-runtime preparation and inference | Explicitly tested Windows + NVIDIA CUDA profiles | No model or hardware profile validated yet |
| Ordinary-user setup | Native core binaries; explicit preparation of managed Python and compatible prebuilt inference dependencies | Installers and runtime packages are not implemented |

The initial core verification targets are the macOS 15.7 arm64 release line,
Windows 10 with exact build and architecture pending inventory, and Ubuntu 24.04
LTS x86-64. These are test targets, not a completed support matrix. Core setup is
intended to work without system Python, local compilation, or automatically
installing inference dependencies.

GPU models, drivers, RAM/VRAM requirements, performance, export formats, and
precision or quantization variants need evidence for each model/runtime profile.
There is no project-wide memory minimum or universal quantization option.
Inference on macOS, Linux, AMD, Apple accelerators, or CPU remains undecided.

## Getting started today

Developer prerequisites are Rust 1.99.1 with rustfmt and Clippy (pinned in
`rust-toolchain.toml`), a native linker/C toolchain (MSVC Build Tools and Windows
SDK on Windows), and Python 3 (standard library only) for the verification scripts. Cargo needs
registry dependencies cached or network access on the first build. OpenSSL-backed
Python TLS verification is required by the public consumer. These are developer
prerequisites, not model-runtime or ordinary-user installation requirements.

Each supported OS has one non-interactive verification command. It runs the
protected-input check, formatting, the build, strict Clippy for the default,
engine `test-support` and platform `native-test-hooks` graphs, and the matching
three test graphs with one harness thread. Every step runs even after a
failure; the command prints a pass/fail summary and exits non-zero if any step
failed. Any engine or test host left running by a failed test is stopped and
counted as a failure.

On Linux (including WSL2) and macOS:

```sh
scripts/verify-unix.sh
```

On Windows, Cargo and containing launcher Job Objects prevent the detached engine
from using the required breakaway lifetime. Run the script from an independent
PowerShell terminal outside such a Job Object; it refuses an unsuitable host,
compiles with Cargo and runs the reported test binaries directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-windows.ps1
```

Do not weaken engine lifetime or security to make it pass. The protected-input
check alone is `python scripts/verify_protected_inputs.py`; it compares the
byte-protected integration tests with the hashes recorded in
`scripts/protected-inputs.json`. Individual graphs can still be run with the
commands the scripts print, for example `cargo test --workspace --all-targets
--locked -- --test-threads=1` after `cargo build -p dissect3d-engine --features
test-support --examples --locked` and the `DISSECT3D_TEST_*` exports in
`scripts/verify-unix.sh`. On Windows, a graph run through `cargo test` executes
inside Cargo's Job Object, so the detached-engine tests cannot pass there; use
`scripts/verify-windows.ps1`, which runs the test binaries directly. Individual concurrency scenarios still execute their
own concurrent operations.

The workspace contains API, platform, connection, engine, and CLI crates.
Use `target/debug/dissect3d --help` (`.exe` on Windows) for implemented commands.
Core verification is incomplete, including CS-N01-CS-N05 deferred manual/fault
criteria. There is no supported installer or validated inference profile yet.

## Contributing

Contributions can help make the intended workflows concrete and testable. Useful
early work includes clarifying user scenarios, investigating model integration
requirements, gathering reproducible platform evidence, and proposing bounded
engine or client contracts.

- **Propose a change:** explain the user problem, the affected component, and the
  observable behavior you want to add. Identify any decisions it depends on.
- **Investigate a model:** identify the upstream revision, required conditioning,
  complete dependencies and assets, licenses, platform constraints, and a
  reproducible validation procedure. Separate upstream evidence from project tests.
- **Change the code:** start with [ARCHITECTURE.md](ARCHITECTURE.md) for where
  things live and which module may depend on which.
- **Submit a pull request:** keep the scope focused, explain the resulting
  behavior, and report what was checked and what remains unverified. Update the
  relevant documentation when behavior or accepted direction changes.

Delivery priorities, the first integrated model, client order, and milestones are
still open. A component's position in this README does not set its delivery order.
Training, cloud or distributed inference, remote engine access, automatic format
conversion, and a general-purpose 3D editor require separate scope decisions.

## License

Dissect3D's own code and documentation are covered by the [MIT license](LICENSE).
Upstream code, model weights, and runtime components retain their respective
licenses and access terms. Integration requires checking those terms separately.
