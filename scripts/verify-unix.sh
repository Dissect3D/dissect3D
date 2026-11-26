#!/usr/bin/env bash
# Full local verification for Linux (including WSL2) and macOS.
#
#   scripts/verify-unix.sh
#
# Non-interactive. Runs the protected-input check, formatting, the build, the
# three strict Clippy graphs and the three test graphs (default workspace,
# engine test-support, platform native-test-hooks) with one harness thread.
# Every step runs even after a failure; a short summary follows and the exit
# status is non-zero if any step failed. Prerequisites are the README's:
# the pinned Rust toolchain, a C toolchain (`cc`), and Python 3.
#
# Each test graph runs with TMPDIR set to its own fresh physical /tmp/d3d.* directory. Afterwards
# any process still naming that directory (a detached engine or test host a
# failed test did not stop) is reported, terminated and counted as a failure.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PYTHON="${PYTHON:-python3}"
RESULTS=""
FAILED=0

record() { # name status
    RESULTS="${RESULTS}$(printf '%-6s %s' "$2" "$1")
"
    [ "$2" = PASS ] || FAILED=$((FAILED + 1))
}

step() { # name command...
    local name="$1"
    shift
    echo "==> $name"
    if "$@"; then record "$name" PASS; else record "$name" FAIL; fi
}

# Stop any process whose command line names this run's temporary directory.
sweep() { # name dir
    local pids
    pids="$(pgrep -f -- "$2" 2>/dev/null | tr '\n' ' ')"
    if [ -n "${pids// /}" ]; then
        echo "leaked processes after $1: $pids"
        ps -o pid=,command= -p ${pids// /,} 2>/dev/null || true
        kill -TERM $pids 2>/dev/null
        local tries=0
        while [ $tries -lt 20 ] && pgrep -f -- "$2" >/dev/null 2>&1; do
            sleep 0.25
            tries=$((tries + 1))
        done
        pids="$(pgrep -f -- "$2" 2>/dev/null | tr '\n' ' ')"
        [ -n "${pids// /}" ] && kill -KILL $pids 2>/dev/null
        record "$1: no leaked processes" FAIL
    else
        record "$1: no leaked processes" PASS
    fi
    rm -rf -- "$2"
}

test_graph() { # name cargo-test-args...
    local name="$1"
    shift
    local tmp_base run_tmp
    # Short on purpose: engine bootstrap sockets live at
    # <data root>/run/bootstrap.sock and must fit sockaddr_un (104 bytes on
    # macOS). The physical path is used because owned roots refuse symlinked
    # ancestors (macOS /tmp -> /private/tmp); only the system /var alias is
    # normalized by the platform.
    tmp_base="$(cd /tmp && pwd -P)"
    run_tmp="$(mktemp -d "$tmp_base/d3d.XXXXXX")" || {
        record "$name" FAIL
        return
    }
    step "$name" env TMPDIR="$run_tmp" cargo test "$@" --locked -- --test-threads=1
    sweep "$name" "$run_tmp"
}

TARGET="$(cargo metadata --format-version 1 --no-deps --locked 2>/dev/null |
    "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
if [ -z "$TARGET" ]; then
    echo "cannot resolve the Cargo target directory (cargo metadata / $PYTHON)"
    exit 2
fi

step "protected inputs" "$PYTHON" -B scripts/verify_protected_inputs.py
step "fmt" cargo fmt --all -- --check
step "build workspace" cargo build --workspace --locked
step "build test-support examples" \
    cargo build -p dissect3d-engine --features test-support --examples --locked
step "clippy default" cargo clippy --workspace --all-targets --locked -- -D warnings
step "clippy engine test-support" cargo clippy -p dissect3d-engine --all-targets \
    --features test-support --locked -- -D warnings
step "clippy platform native-test-hooks" cargo clippy -p dissect3d-platform --all-targets \
    --features native-test-hooks --locked -- -D warnings

export DISSECT3D_TEST_ENGINE="$TARGET/debug/dissect3d-engine"
export DISSECT3D_TEST_CLI="$TARGET/debug/dissect3d"
export DISSECT3D_TEST_DISCOVERY_ENGINE="$TARGET/debug/examples/discovery_test_host"
export DISSECT3D_TEST_SUBMISSION_ENGINE="$TARGET/debug/examples/submission_test_host"
export DISSECT3D_TEST_SUBMISSION_TOOL="$TARGET/debug/examples/submission_fixture_tool"

test_graph "tests default workspace" --workspace --all-targets
test_graph "tests engine test-support" -p dissect3d-engine --features test-support --lib --tests
test_graph "tests platform native-test-hooks" -p dissect3d-platform --features native-test-hooks \
    --lib --tests

echo
echo "Summary ($(uname -s) $(uname -m)):"
printf '%s' "$RESULTS"
if [ "$FAILED" -ne 0 ]; then
    echo "FAILED: $FAILED step(s)"
    exit 1
fi
echo "ALL PASSED"
