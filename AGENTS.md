# Dissect3D repository guidance

These instructions apply throughout the repository unless a more specific
AGENTS.md supplies additional guidance for its directory. Read [README.md](README.md)
first for the project's purpose, intended workflows, architecture, and current state.

## Current state and starting work

Dissect3D is at the requirements and architecture stage. There is no implemented
engine, client, installer, model adapter, build system, or runtime test suite.
Established direction describes what to build; it is not evidence of working
software or supported hardware.

- Start with the user's requested outcome and inspect the files relevant to it.
  Read additional tracked specifications and scoped instructions when they exist.
- Use normal coding-agent behavior by default. Do not require a workflow-selection
  question or a personal toolkit. Follow a workflow or skill when the user selects it.
- Keep public guidance usable from a clean clone. Untracked notes, ignored folders,
  personal preferences, and private documentation must not be prerequisites.
- User instructions and confirmed requirements govern. Identify material conflicts
  between documentation, implementation, and upstream behavior before dependent work.
  Distinguish accepted decisions, proposals, implemented behavior, and verified support.
- Keep changes focused. Preserve unrelated user work and do not scaffold an
  application, choose a first model, or expand scope as a side effect of a
  documentation or research task.

## Architecture to preserve

The following are accepted design constraints; implementation is pending.

| Boundary | Constraint |
| --- | --- |
| Engine authority | One per-OS-user Rust engine owns support resolution, model inventory, runtime preparation, readiness, durable jobs, resource reservations, and published results |
| Clients | CLI, Desktop, Blender, and Unity use the common public engine contract; clients and workers never access the engine database directly |
| Public API | HTTP/JSON control operations, polling sufficient for correct monitoring, and resumable SSE; transfer large inputs and artifacts separately |
| Persistence | SQLite behind an engine persistence interface; large inputs, weights, and meshes are external files |
| Execution | Supervised worker processes execute model adapters and upstream pipelines; Python/native inference dependencies stay in managed environments outside client hosts |
| Local access | Loopback-only service with revocable per-client credentials and consistent authorization for control, events, and artifacts; enforce browser-origin and Host policies |

Logical engine modules do not imply separate services or a predetermined source
tree. Rust libraries, client languages/frameworks, worker transport, provisioning
tools, installer technology, and exact schemas remain unselected. Rust orchestrates
workers; it is not a claim of faster GPU inference.

## Behavioral constraints

### Models and preparation

- Distinguish a model family, exact implementation, task, pipeline, adapter,
  assets, runtime profile, variant, and tested support profile. Required masks,
  part counts, mesh conditioning, and output differences survive the common adapter
  boundary. Reject unsupported options instead of ignoring them.
- Preserve upstream preprocessing, inference, and postprocessing where practical.
  Record intentional modifications. Engine job scheduling and a pipeline's sampling
  scheduler are different responsibilities.
- OmniPart targets image-plus-part-mask generation; PartCrafter targets
  image-plus-part-count generation. The Hunyuan target is existing-mesh part
  segmentation/completion, with Hunyuan3D-Part as the candidate implementation.
  None is currently integrated or validated.
- Capture exact adapter, executed source, asset, runtime, and variant revisions.
  Released support definitions and activated environments are immutable. Managed
  profiles may use recorded forks, patches, and maintainer-built prebuilt components.
- Preparation is an explicit engine-owned operation. Ordinary users should not
  need system Python or local source compilation. Stage and verify replacements
  before activation; failed replacement preserves the prior installation.
- Installed files, verified readiness, current execution eligibility, authorization,
  and loaded-in-memory state are separate facts. A download or cache hit establishes
  none of the other states by itself.
- Prepared local execution works offline without hidden downloads, external
  preprocessing/inference, or telemetry. Do not promise offline first-time setup.

### Jobs, resources, and results

- Accept a job durably before execution, capturing resolved configuration and
  complete immutable input snapshots. Client disconnection does not cancel it.
  Support idempotent submission without claiming exactly-once GPU execution.
- Cancellation records intent and establishes worker/process-tree cleanup before
  treating resources as released. Restart preserves committed outcomes, rechecks
  queued jobs, and marks uncommitted active attempts interrupted. Retry creates a
  new linked job explicitly; never silently rerun uncertain execution.
- Use bounded queues and FIFO ordering among eligible jobs. Keep reservations
  central, including idle loaded allocations and coordinated multi-device needs.
  One attempt per worker and, by default, one GPU attempt per device are the
  accepted conservative policies. Worker reuse and greater concurrency need validation.
- Validate mandatory geometry and structure before publishing success. File
  existence, process exit, and nominal part count are insufficient. Partial results
  require declared task semantics and explicit missing or invalid components.
- Publish artifacts with versioned manifests covering integrity, part relationships,
  transforms, coordinate conventions, units, materials, provenance, and validation.
  Unknown metadata stays explicit. Do not assume a universal output format or converter.
- Retain published results and captured inputs until explicit deletion or a
  user-enabled retention policy. Protect shared and nonterminal references. Removing
  model installations must not implicitly delete results.
- Confine input/artifact references to their authorized boundaries. Keep credentials,
  raw inputs, and unnecessary personal paths out of normal diagnostics. Process and
  dependency isolation do not constitute a security sandbox.

### Clients and platforms

- CLI is an engine client, with human-readable and structured scripting output.
  Foreground execution, detached submission, observation, cancellation, and local
  result saving have different promises. Preserve them when defining exact contracts.
  The planned command name is `dissect3d`; accepted groups include `run`, `engine`,
  `models`, `runtimes`, `tasks`, `operations`, `jobs`, `results`, `storage`, `config`,
  `auth`, and `diagnostics`. Commands are not implemented. Foreground run interruption
  requests cancellation; stopping observation alone does not cancel accepted work.
- Desktop's initial scope is management, monitoring, and 3D preview. Editing,
  model-driven modifications, and automatic conversion need separate requirements.
- CLI and engine target bounded Windows, macOS, and Linux core operation independently
  of Desktop and inference dependencies. Initial preparation/inference targets tested
  Windows/NVIDIA CUDA profiles only. The README records the initial core test targets;
  none has completed application verification.
- Treat quantization as a per-model, per-runtime capability. Precision, offloading,
  sampling effort, and mesh simplification are distinct. No project memory floor,
  universal Q4/Q8 option, or unmeasured performance guarantee exists.
- Keep first-model selection, client order, delivery priorities, and milestones open.
  Remote access, cloud/distributed inference, training, and a general-purpose editor
  require explicit scope decisions.

## Documentation and repository structure

- README owns the public introduction, status, workflows, architecture summary,
  navigation, and contribution entry points. AGENTS.md owns actionable repository
  guidance. Both must be understandable without personal documentation.
- Add detailed public documentation when its scope is selected. Link to tracked
  governing documents once available; do not create empty documentation trees or
  speculative source directories. Keep requirements, architecture, contracts, and
  implementation plans distinct as those artifacts become necessary.
- Preserve existing feature slugs and requirement identifiers in documents being
  updated. Record material changes to accepted scope and reconcile affected public
  summaries. Never invent user confirmation, benchmarks, or completed acceptance.
- Use plain English and explain responsibilities and observable behavior. Label
  planned components clearly. Installation commands, screenshots, support badges,
  and runnable examples must correspond to actual project artifacts.
- Keep credentials, model weights, managed environments, generated geometry, and
  personal workflow files out of version control. Do not change the project's MIT
  license or imply it grants rights to upstream assets.

## Verification and handoff

For documentation changes, check relative links and anchors against publishable
repository files, terminology, status claims, identifiers where present, and
consistency between README and agent guidance. Use `git diff --check` for tracked
changes and check new files too. Report these as documentation checks.

There are no build, lint, or runtime test commands yet. Do not install GPU runtimes,
download weights, or add application scaffolding to verify documentation. Once
implementation exists, follow its documented commands and run checks appropriate
to the changed behavior. Never report unexecuted tests as passing.

When model or dependency behavior matters, inspect primary upstream sources and
record the revision, or inspection date with the limitations of a mutable source.
A supported model requires validation of its adapter, assets, declared tasks,
runtime, hardware, and output behavior together. Upstream Linux execution does
not establish Windows support; project-managed patches may establish support only
with evidence for the resulting configuration.

At handoff, state what changed, what was checked, what remains open, and which
external or hardware acceptance criteria remain unverified.
