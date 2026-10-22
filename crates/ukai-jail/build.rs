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
    if target.contains("apple-darwin") {
        compile_es_shim();
    }
    // The bindings in `platform/macos/es/mod.rs` have landed, so the
    // guardian's custody facade (`platform/macos/custody_io.rs`) always
    // compiles against them; the probe and the facade's fallback branch are
    // gone (its TODO-EsShim).
    println!("cargo:rustc-check-cfg=cfg(es_shim_present)");
    println!("cargo:rustc-cfg=es_shim_present");
}

/// Compiles the fixed-size ES custody shim (`shim.c`, jail-macos §4.1,
/// §4.3) with `-Werror` under C99 and links the EndpointSecurity and
/// CoreFoundation frameworks. EndpointSecurity is linked as
/// `-lEndpointSecurity`: its tbd stub ships in the SDK's `usr/lib` on every
/// installed SDK here, while no SDK carries an
/// `EndpointSecurity.framework` directory for `-framework` to find.
#[cfg(target_os = "macos")]
fn compile_es_shim() {
    cc::Build::new()
        .file("src/platform/macos/es/shim.c")
        .include("src/platform/macos/es")
        .file("src/platform/macos/observe/obs_shim.c")
        .include("src/platform/macos/observe")
        .flag("-std=c99")
        .flag("-Werror")
        .compile("ukai_es_shim");
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}

// The `cc` build-dependency is declared under
// `[target.'cfg(target_os = "macos")'.build-dependencies]`, matched against
// the host, so a Linux-target build never needs it and never sees this.
#[cfg(not(target_os = "macos"))]
fn compile_es_shim() {}

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
