# Dissect3D agent guidance

## Project state and reading order

Dissect3D has a Rust core-service implementation with native platform,
connection/readiness, authenticated API, SQLite engine, and connected CLI
packages, read-only support discovery, and bounded durable queued
submission/recovery/list/show. Current core acceptance is incomplete; the README
status and the maintainers' feature records list passed evidence and explicit
native/non-native gates. Worker supervision and result publication run only in an
explicit Unix test-support host; the normal engine keeps dispatch inactive and
publishes nothing. Production model/runtime management and inference, Desktop,
plugins, and installers are not implemented.

1. Read [README.md](README.md) for the project and current state.
2. Read [ARCHITECTURE.md](ARCHITECTURE.md) for the crate map, allowed
   dependency directions and test locations.
3. Verify with the single per-OS command in
   [README](README.md#getting-started-today) (`scripts/verify-unix.sh` or
   `scripts/verify-windows.ps1`); protected tests are listed in
   `scripts/protected-inputs.json`.
4. The maintainers' requirements, contracts, plans and evidence live in a
   separate private `patompong-docs` checkout. When it is present, read
   `patompong-docs/docs/engineering.md`, `docs/roadmap.md` and the matching
   `features/<feature>/{contract.md,plan.md,state.json,log.md}`. It is not
   required to build, test or verify the code.
5. Inspect matching code and tests. Read only the selected workflow and the
   skill dependencies needed for the session.

User instructions and confirmed requirements govern. If documents, code, or
upstream behavior disagree, identify the conflict before dependent work. Describe
implemented behavior, accepted direction, architectural proposals, and unverified
support separately.

## Established project direction

- Follow Ollama's local-service approach: one local engine serves CLI, Desktop,
  Blender, and Unity clients through a common API.
- The engine owns the shared model inventory, runtime preparation, hardware and
  resource management, accepted jobs, and generated artifacts.
- Keep model execution in supervised workers and dependencies in managed,
  compatible environments, outside Blender and Unity host environments.
- Use a common adapter lifecycle with declared task capabilities. Preserve each
  model's required inputs and upstream pipeline behavior.
- Distinguish a model family, a task, a pipeline, model assets, and a runtime
  profile. The Hunyuan target is mesh-input part processing; Hunyuan3D-Part is a
  candidate implementation for segmentation and completion.
- Windows with NVIDIA CUDA is the initial inference target. Managed Python and
  compatible prebuilt dependencies are the intended ordinary-user setup.
- Desktop is intended for preview. Editing and model-driven modifications need
  later requirements before inclusion.
- Quantization is a per-model, per-runtime capability. Precision changes,
  offloading, and mesh simplification are separate concepts.
- Keep delivery priorities open. The overview checklist does not authorize a
  first model, a client order, a technology stack, or an implementation schedule.

## Documentation ownership and continuity

- Keep project requirements and system context under `patompong-docs/docs/`.
  Keep portable workflow/toolkit content under `.agents/` reusable and free of
  project notes, model files, credentials, and generated output.
- README owns the short project introduction and navigation. Requirements own
  scope and observable expectations; system documents explain architecture;
  the glossary owns vocabulary. Link to the governing source instead of copying
  whole specifications into several files.
- Use stable feature slugs and requirement identifiers. Preserve them during
  updates; record material changes to accepted scope and affected artifacts.
- Maintain concise status, acceptance evidence, unresolved decisions, and next
  session context in the documents being changed. Do not invent confirmation,
  benchmark results, support claims, or a completed implementation.
- Detailed protocols, schemas, executable tests, and implementation plans belong
  to their separately selected workflows. Create their directories when those
  artifacts are actually needed.
- Root README and agent guidance are explicitly assigned project files. Keep
  their references aligned when governing requirements change.

## Evidence and verification

- Check primary upstream sources when model or dependency behavior matters.
  Record the inspected revision when available, otherwise the date and the
  limitation of a mutable source. The pasted concept is context, not proof.
- A model is a target until its adapter, assets, runtime, hardware profile, and
  declared tasks are integrated and validated. An upstream Linux demonstration
  does not establish Windows support.
- No model has a confirmed project memory floor or quantized variant. Do not
  turn the pasted 8 GB suggestion into a support promise.
- For documentation changes, verify local links, vocabulary, identifiers,
  status, and consistency. Report these as documentation checks.
- Select meaningful runtime tests when implementation work exists. Do not
  install GPU runtimes, download weights, or create application scaffolding just
  to verify overview documentation.
- At handoff, state what changed, what was checked, what remains open, and any
  unverified external or hardware acceptance criteria.
