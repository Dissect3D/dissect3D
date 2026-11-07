# Controlled CPU preparation probe

The `submission_fixture_tool probe-cpu` mode checks the installed package and
probe binary by exact SHA-256, writes and reads a private bounded file, checks
the read-back digest, and runs the registered fixture OBJ validator against its
known tetrahedron and a deliberately invalid variant. It does not schedule a
job, start a worker, download assets, or claim model inference readiness.
