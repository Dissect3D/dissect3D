//! Build closure of the r2 execution-fixture worker (WE-P05/3, test-only use).
//!
//! Hashes every file of this crate and of each workspace crate it depends on
//! by path (found transitively from the manifests, so `include_bytes!` targets
//! under `tests/` are covered too), plus the workspace manifest, the lockfile
//! (which pins every registry crate by checksum), toolchain/Cargo
//! configuration when present, the exact rustc release, the target, and this
//! build's profile, features and rustflags (flags as a digest). The
//! sorted manifest goes to `OUT_DIR/worker_closure.txt` and its SHA-256 to
//! `D3D_R2_WORKER_CLOSURE_SHA256`; the worker embeds that digest and
//! preparation refuses a worker built from any other closure. Over-coverage is
//! deliberate: any change to these crates changes the identity (fails closed).
//! Like Cargo's own fingerprints this identifies the build inputs; it is not a
//! reproducible-build proof.
#![expect(
    clippy::expect_used,
    reason = "build script: a panic is Cargo's build-failure report and fails the build closed"
)]
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Workspace crates this crate depends on by path, transitively (all
/// dependency tables, optional ones included).
fn path_crates(start: &Path) -> Vec<PathBuf> {
    let mut crates: Vec<PathBuf> = Vec::new();
    let mut pending = vec![canonical(start)];
    while let Some(dir) = pending.pop() {
        if crates.contains(&dir) {
            continue;
        }
        let manifest = std::fs::read_to_string(dir.join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for line in manifest.lines() {
            let Some((_, rest)) = line.split_once("path = \"") else {
                continue;
            };
            let Some((value, _)) = rest.split_once('"') else {
                continue;
            };
            let target = dir.join(value);
            // `[[test]] path = "tests/x.rs"` names a file, not a crate.
            if target.join("Cargo.toml").is_file() {
                pending.push(canonical(&target));
            }
        }
        crates.push(dir);
    }
    crates.sort();
    crates
}

fn relative(workspace: &Path, path: &Path) -> String {
    let rest = path
        .strip_prefix(workspace)
        .unwrap_or_else(|_| panic!("{} is outside the workspace", path.display()));
    let parts: Vec<&str> = rest
        .components()
        .map(|c| {
            c.as_os_str()
                .to_str()
                .filter(|s| !s.contains(['\n', '\r', '\t']))
                .unwrap_or_else(|| panic!("unsupported path {}", path.display()))
        })
        .collect();
    parts.join("/")
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("{}: {e}", entry.path().display()));
        if kind.is_dir() {
            walk(&entry.path(), files);
        } else if kind.is_file() {
            files.push(entry.path());
        } else {
            // A link or special file could stand for anything: refuse.
            panic!("unsupported entry {}", entry.path().display());
        }
    }
}

fn rustc_identity() -> String {
    let rustc = std::env::var_os("RUSTC").expect("cargo sets RUSTC");
    let output = std::process::Command::new(rustc)
        .arg("-vV")
        .output()
        .expect("rustc -vV runs");
    assert!(output.status.success(), "rustc -vV failed");
    let text = String::from_utf8(output.stdout).expect("rustc -vV is UTF-8");
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
            .unwrap_or_else(|| panic!("rustc -vV lacks {key}"))
            .to_owned()
    };
    format!("{} {}", field("release:"), field("commit-hash:"))
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo"));
    let workspace = canonical(
        manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("crates/<name> layout"),
    );
    let root_manifest = std::fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace");
    assert!(root_manifest.contains("[workspace]"), "workspace root");

    let mut files = Vec::new();
    let crates = path_crates(&manifest_dir);
    for dir in &crates {
        walk(dir, &mut files);
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain",
        "rust-toolchain.toml",
        ".cargo/config",
        ".cargo/config.toml",
    ] {
        let path = workspace.join(name);
        if path.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push(path);
        }
    }
    let mut lines: Vec<String> = files
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            format!(
                "file {} {}",
                hex(&Sha256::digest(&bytes)),
                relative(&workspace, path)
            )
        })
        .collect();
    lines.sort_by(|a, b| a[70..].cmp(&b[70..]));
    lines.push(format!("rustc {}", rustc_identity()));
    lines.push(format!(
        "target {}",
        std::env::var("TARGET").expect("cargo sets TARGET")
    ));
    // Build configuration that changes the compiled code: profile, features
    // and flags (flags as a digest, so no local paths enter the report).
    let var = |key: &str| std::env::var(key).unwrap_or_else(|_| panic!("cargo sets {key}"));
    lines.push(format!(
        "profile {} opt-level {} debug {}",
        var("PROFILE"),
        var("OPT_LEVEL"),
        var("DEBUG")
    ));
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_lowercase))
        .collect();
    features.sort();
    lines.push(format!("features {}", features.join(",")));
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    lines.push(format!(
        "rustflags {}",
        hex(&Sha256::digest(flags.as_bytes()))
    ));
    let mut manifest = lines.join("\n");
    manifest.push('\n');
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(out.join("worker_closure.txt"), &manifest).expect("write closure manifest");
    println!(
        "cargo:rustc-env=D3D_R2_WORKER_CLOSURE_SHA256={}",
        hex(&Sha256::digest(manifest.as_bytes()))
    );
}
