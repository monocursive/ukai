/// Classify only after the independent fixture has observed a valid outcome.
pub fn kernel_rejects_arm32() -> bool {
    let output = std::process::Command::new("/usr/bin/python3")
        .args([
            "-I",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/arm64_exec_control.py"
            ),
            "--classify",
        ])
        .output()
        .expect("run the ARM32 control");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ARM32 control result");
    match result["arm32_exec"].as_str() {
        Some("succeeded") => false,
        Some("ENOEXEC") => true,
        _ => panic!("unexpected ARM32 control result: {result}"),
    }
}
