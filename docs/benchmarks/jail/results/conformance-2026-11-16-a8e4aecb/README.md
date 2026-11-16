# Strict Linux conformance — 16 November 2026

[Reference run 43817218080](https://github.com/monocursive/ukai/actions/runs/43817218080)
passed on its first attempt at exact commit
`a8e4aecb071a0367001f309a659897d6aa336600`, with runtime inputs
`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.

The suite passed 3,073 tests across 117 groups, with zero failures, 18 explicitly
ignored tests and zero runtime capability skips. Both D2 integration
tests, managed native gate checks and the recorded K11/K27 release-evidence
checks executed and passed. The run's own doctor reports a ready, clean,
optimized Linux x86_64 build with that exact commit and input digest.

The gate report has no problems or warnings for `linux-preview`. It retains
65 pass, seven pass-with-limits, three pass-with-unsupported, 21 unsupported,
13 elsewhere and one credential row. `all_noncredential_gates_pass` remains
false: this result does not qualify the full specification, native macOS,
the new managed VM image or the earlier failed Claude API lanes.

All 16 original artifact files are unchanged; [retention.json](retention.json)
records their hashes and sizes. The raw gate report retains two stale descriptive
notes about the older onboarding evidence. Its actual K11/K27 tests verified the
[current evidence index](../../release-preview-current.json): the November 16
run measured 152.031644 seconds from installation to the first contained agent,
excluding VM bootstrap. Learning proposed only `/etc/nsswitch.conf`, leaving
15 unresolved reads ungranted. The notes are corrected separately in source.

This conformance result supports generating a tested freeze. A later candidate
commit still needs its own required checks and native artifact validation.
No public release or tag is established by this evidence.
