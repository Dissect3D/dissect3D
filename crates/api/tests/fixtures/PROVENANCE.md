# Submission protocol vectors

`submission-vectors.json` is an exact copy of the ds-0.1 submission vectors
reviewed on 2026-11-07. It supplies independent literal expectations to both
API protocol and engine canonicalization tests.

The original review package is workspace documentation. Rust tests use this
repository copy so a clean source checkout has no dependency on personal notes.
Changing expected semantics requires contract review; do not regenerate these
expectations from the implementation under test.
