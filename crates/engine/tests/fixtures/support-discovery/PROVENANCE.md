# Support discovery fixtures

These JSON files are exact copies of the sd-1.1 controlled discovery fixtures
reviewed on 2026-11-07. They retain the original declaration, identity, schema,
and literal-vector expectations. They describe test support only.

The original protected review package remains unchanged. Rust tests and the
feature-gated discovery host use these repository files so compilation does
not depend on ignored workspace documentation. Changes to expected behavior
require contract review; do not regenerate expectations from production code.
