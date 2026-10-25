# Dissect3D

**Local AI for 3D generation and part processing.**

Dissect3D is an open-source project building a shared local engine for turning
images into 3D assets and processing existing meshes into parts. The goal is to
prepare models once, run them on your own hardware, and use the same jobs and
results from a terminal, a desktop application, Blender, or Unity.

**Status: early design; no runnable application yet.** The project has established
its core requirements and engine direction. The engine, clients, installers, and
model adapters have not been implemented. Everything described below is intended
behavior unless explicitly identified as available today.

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
loopback with per-client authorization. These are design decisions; their
implementation and validation are pending.

Client languages and frameworks, runtime provisioning tools, installer technology,
exact API schemas, and source-directory layout remain open.

## Platform direction

Core application support and model inference support have separate validation
requirements.

| Area | Target | Current evidence |
| --- | --- | --- |
| CLI and engine installation and operation | Bounded Windows, macOS, and Linux targets, independently of Desktop | No application verification yet |
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

There is no Dissect3D installation, build, or inference command to run yet. Start
with this README to understand the project, and [AGENTS.md](AGENTS.md) for repository
conventions and guidance for coding agents. Dedicated public documentation will
be added as the project develops.

The public repository's current project files are:

```text
README.md       Project purpose, intended behavior, architecture, and status
AGENTS.md       Repository guidance for coding agents and contributors
LICENSE         MIT license
.gitignore      Repository exclusions
```

The architecture above describes logical components; it does not imply that
engine, client, adapter, or test directories already exist.

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
