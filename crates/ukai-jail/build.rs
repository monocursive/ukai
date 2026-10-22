//! Build provenance for `version --json` and `doctor --json` (jail-v1 §16:
//! "Freeze the Rust toolchain ... observer object/build provenance").
//!
//! Records, at compile time, what was measured rather than asserted (review
//! F8): the compiler's own `rustc -V`, the target triple, the opt-level cargo
//! compiled this crate at, and a digest of the build inputs
//! (`src/build_provenance.rs` states the rule). It validates the driver's
//! `UKAI_BUILD_REVISION` / `UKAI_BUILD_DIRTY` claims and fails the build on a
//! malformed or contradictory one; where the repository's `.git` is present,
//! it also checks them against git itself.

#[path = "src/build_provenance.rs"]
mod build_provenance;

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits at crates/ukai-jail")
        .to_path_buf();

    // Every input the digest covers reruns this script when it changes;
    // the environment claims are read here, so they rerun it too.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    for file in build_provenance::INPUT_FILES {
        println!("cargo:rerun-if-changed={}", root.join(file).display());
    }
    println!("cargo:rerun-if-env-changed=UKAI_BUILD_REVISION");
    println!("cargo:rerun-if-env-changed=UKAI_BUILD_DIRTY");

    let claims = build_provenance::validate(
        std::env::var("UKAI_BUILD_REVISION").ok().as_deref(),
        std::env::var("UKAI_BUILD_DIRTY").ok().as_deref(),
    )
    .unwrap_or_else(|error| panic!("ukai-jail build provenance: {error}"));
    check_against_git(&root, &claims);

    let inputs = build_provenance::tree_digest(&root)
        .unwrap_or_else(|error| panic!("ukai-jail build provenance: the inputs: {error}"));
    println!("cargo:rustc-env=UKAI_BUILD_INPUTS={inputs}");

    // `RUSTC` is the compiler cargo uses for this crate; `-V` is its own
    // version line, commit and date included. A compiler that cannot say
    // is recorded as unknown, never guessed from the toolchain file.
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty() && !text.contains('\n'))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=UKAI_BUILD_RUSTC={version}");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=UKAI_BUILD_TARGET={target}");

    // `OPT_LEVEL` is the level this crate is compiled at, whatever the
    // profile is called (a custom profile inheriting `release` can say 0).
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=UKAI_BUILD_OPT_LEVEL={opt_level}");

    // The ES custody shim (jail-macos §4.1) is compiled only for macOS
    // targets: the build script itself runs on the host, so the target
    // decides. The frameworks are linked here, not in Cargo.toml. The shim
    // lives under `src/`, so the build provenance digest covers it.
    println!("cargo:rerun-if-changed=src/platform/macos/es/shim.c");
    println!("cargo:rerun-if-changed=src/platform/macos/es/shim.h");
    // The J17 observation shim (jail-macos §5) compiles into the same
    // static library: all its symbols are `ukai_obs_*`, so the two shims
    // cannot clash.
    println!("cargo:rerun-if-changed=src/platform/macos/observe/obs_shim.c");
    println!("cargo:rerun-if-changed=src/platform/macos/observe/obs_shim.h");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        compile_es_shim(&target);
    }
}

/// Build the Darwin-target shims regardless of the build script's host.
/// `cc` is a host-conditional dependency in this crate; using the compiler
/// directly here also supports Linux hosts with a Darwin clang and SDKROOT.
/// A missing compiler/SDK fails the build instead of linking without a shim.
fn compile_es_shim(target: &str) {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let compiler_key = format!("CC_{}", target.replace('-', "_"));
    let archiver_key = format!("AR_{}", target.replace('-', "_"));
    let flags_key = format!("CFLAGS_{}", target.replace('-', "_"));
    for key in [
        &compiler_key,
        &archiver_key,
        &flags_key,
        "CC",
        "AR",
        "CFLAGS",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    // Without an explicit compiler, prefer the Xcode toolchain's clang over
    // whatever `clang` comes first on PATH: an older toolchain (a Swift
    // toolchain's clang, for one) cannot parse the macOS 27 SDK headers.
    let compiler = std::env::var_os(&compiler_key)
        .or_else(|| std::env::var_os("CC"))
        .or_else(|| xcrun_find("clang"))
        .unwrap_or_else(|| "clang".into());
    let archiver = std::env::var_os(&archiver_key)
        .or_else(|| std::env::var_os("AR"))
        .unwrap_or_else(|| "ar".into());
    let sdk = std::env::var_os("SDKROOT").or_else(|| {
        // xcrun is a discovery convenience on a Darwin host, never the
        // condition deciding whether to compile a Darwin target's shim.
        Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().into())
    });
    let mut objects = Vec::new();
    for (name, source) in [
        ("custody", "src/platform/macos/es/shim.c"),
        ("observe", "src/platform/macos/observe/obs_shim.c"),
    ] {
        let object = out.join(format!("{name}.o"));
        let mut command = Command::new(&compiler);
        command
            .args([
                "-target", target, "-fblocks", "-std=c11", "-Werror", "-c", source, "-o",
            ])
            .arg(&object);
        if let Some(sdk) = &sdk {
            command.arg("-isysroot").arg(sdk);
        }
        if let Ok(flags) = std::env::var(&flags_key).or_else(|_| std::env::var("CFLAGS")) {
            command.args(flags.split_whitespace());
        }
        if let Ok(level) = std::env::var("OPT_LEVEL") {
            command.arg(format!("-O{level}"));
        }
        checked_command(&mut command, "compile Darwin ES shim");
        objects.push(object);
    }
    let archive = out.join("libukai_es_shim.a");
    // `ar crs` adds to an existing archive, and OUT_DIR survives build.rs
    // changes: an earlier build's members (the `cc` crate's hashed objects)
    // would otherwise stay in it and link twice.
    match std::fs::remove_file(&archive) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale Darwin ES shim archive: {error}"),
    }
    let mut command = Command::new(archiver);
    command.arg("crs").arg(&archive).args(&objects);
    checked_command(&mut command, "archive Darwin ES shim");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=ukai_es_shim");
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}

/// The Xcode toolchain's path for `tool`, when `xcrun` exists and knows it.
fn xcrun_find(tool: &str) -> Option<std::ffi::OsString> {
    Command::new("xcrun")
        .args(["--find", tool])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().into())
        .filter(|s: &std::ffi::OsString| !s.is_empty())
}

fn checked_command(command: &mut Command, step: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{step}: {error}"));
    assert!(status.success(), "{step}: {status}");
}

/// Where the repository's `.git` is present and git runs, a named revision
/// must be `HEAD` and a clean claim must hold for the build inputs; a
/// contradiction fails the build. Without `.git` (the driver's copy) the
/// claims stand as given, and `inputs` is what `cargo xtask freeze` checks
/// them against later.
fn check_against_git(root: &Path, claims: &build_provenance::Claims) {
    let Some(revision) = claims.revision.as_deref() else {
        return;
    };
    if !root.join(".git").exists() {
        return;
    }
    let git = |args: &[&str]| -> Option<String> {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let Some(head) = git(&["rev-parse", "HEAD"]) else {
        println!("cargo:warning=UKAI_BUILD_REVISION could not be checked: git did not answer");
        return;
    };
    if head != revision {
        panic!(
            "ukai-jail build provenance: UKAI_BUILD_REVISION={revision} but the repository's \
             HEAD is {head}"
        );
    }
    if claims.dirty == Some(false) {
        let mut args = vec![
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            build_provenance::INPUT_DIR,
        ];
        args.extend(build_provenance::INPUT_FILES);
        match git(&args) {
            Some(changes) if !changes.is_empty() => panic!(
                "ukai-jail build provenance: UKAI_BUILD_DIRTY=false but the build inputs \
                 differ from {revision}:\n{changes}"
            ),
            Some(_) => {}
            None => println!("cargo:warning=UKAI_BUILD_DIRTY could not be checked"),
        }
    }
}
