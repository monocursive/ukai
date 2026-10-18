# rc.3 preview evidence: first attempt, blocked at the doctor sweep

The first clean-VM run for revision `d4988945e53322b0c0182aabf3efea502cf4512d`
(build inputs `sha256:32e294a36c9d1dffd23ed2e9afc3ec8a87148e2b8cda26538d22737feffbaf89`),
kept unchanged. Not current evidence; the passing run is
[release-preview-2026-10-18-rc3](../release-preview-2026-10-18-rc3/README.md).

The onboarding workflow (65.5 s), the learning workflow and the distribution
checks passed, with the provider key vaulted as in the passing run. The
guest's `doctor` sweep then ran from the guest's home directory, which
`doctor` takes as the workspace, and `doctor --launch claude` refused:

```text
ukai-jail: error invalid_config at resolving [configuration]: credential `anthropic` lies inside a grant the child can write (key: launch.credentials.anthropic.source)
```

The bundled `claude` profile can use the `anthropic` key that `credential set`
had stored under the guest's config directory, and that directory lay inside
the home-as-workspace. The refusal is the placement rule working; earlier runs
stored no credential, so they never reached it. The harness now runs the sweep
from the project directory. Running `doctor` from home after `credential set`
still gives this message rather than saying that home cannot be a workspace,
which is a usability follow-up for the jail, not a containment failure.

The runner's key scan found the key in none of the 63 recorded files.
