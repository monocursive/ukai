# GitHub-hosted runners: can `ukai-jail` run contained? — 21 October 2026

A spike for a receipt-posting GitHub Action: does Ukai Jail 0.1.0-rc.4 run
contained on GitHub's hosted Linux runners, and if not, what is the smallest
change that makes it? One workflow run
([39657833549](https://github.com/monocursive/ukai/actions/runs/39657833549),
from the throwaway branch `spike/gha-runner-userns`, commit `dc2cd2641`) probed
three hosted images with the same script. Its workflow is
[harness/spike-runner-userns.yml](results/github-runners-2026-10-21/harness/spike-runner-userns.yml)
and every file it collected is in
[the results directory](results/github-runners-2026-10-21/).

**Answer: not stock, but with two disclosed setup steps, yes.** On
`ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm` (aarch64), with bubblewrap 0.11.1
built from its pinned release tarball and a one-binary AppArmor profile that
allows that `bwrap` a user namespace, `doctor` is ready for `tool` and `agent`,
the guide's first command settles, and an `agent` run reaches an allowed host
through the proxy with all six evidence classes active. `ubuntu-22.04` cannot
run this preview at all (glibc 2.35).

## What ran

Each image installed `ukai-jail` 0.1.0-rc.4 with the public installer exactly
as published (`eb9b67b18`, inputs `sha256:893f8568…`), then ran the same
checks under four variants, cumulatively and in this order:

1. **stock**: the distribution's `bubblewrap` from apt;
2. **bwrap 0.11.1**: bubblewrap 0.11.1 built with meson from
   `bubblewrap-0.11.1.tar.xz` (SHA-256
   `c1b7455a1283b1295879a46d5f001dfd088c0bb0f238abb5e128b3583a246f71`, the
   reference host's version) into `/usr/local/bin`, first on `PATH`; nothing
   else changed;
3. **+ AppArmor profile**: variant 2 plus this profile, loaded with
   `apparmor_parser -r` and removed again after the checks:
   ```
   abi <abi/4.0>,
   include <tunables/global>
   profile ukai-bwrap-spike /usr/local/bin/bwrap flags=(unconfined) {
     userns,
   }
   ```
   Ubuntu 24.04 grants user namespaces to other sandboxing programs this way;
   from 24.10 on it ships `bwrap-userns-restrict` for `/usr/bin/bwrap` (the
   reference host's), which 24.04 does not have;
4. **+ sysctl**: variant 2 with
   `kernel.apparmor_restrict_unprivileged_userns=0` on the runner.

The checks, per variant: a direct `bwrap --unshare-user` probe; `doctor
--profile tool|agent` (JSON and text); the guide's first command under `tool`
(`printf … > greeting.txt`, wall 30 s); an `agent` run of `curl
https://api.github.com/zen` with `--allow-host api.github.com` (wall 60 s); `tail
--summary` after each run, and the receipts.

## Results

| Runner | Variant | bwrap | `bwrap` probe | `doctor` tool / agent | `tool` run | `agent` run |
| --- | --- | --- | --- | --- | --- | --- |
| ubuntu-24.04 | 1 stock | 0.9.0 | uid map: Permission denied | not ready / not ready | refused, 125 | refused, 125 |
| ubuntu-24.04 | 2 bwrap 0.11.1 | 0.11.1 | uid map: Permission denied | not ready / not ready | refused, 125 | refused, 125 |
| ubuntu-24.04 | 3 + AppArmor profile | 0.11.1 | ok | ready / ready | settled, 0 | settled, 0, HTTP 200 |
| ubuntu-24.04 | 4 + sysctl | 0.11.1 | ok | ready / ready | settled, 0 | settled, 0, HTTP 200 |
| ubuntu-24.04-arm | 1 stock | 0.9.0 | uid map: Permission denied | not ready / not ready | refused, 125 | refused, 125 |
| ubuntu-24.04-arm | 2 bwrap 0.11.1 | 0.11.1 | uid map: Permission denied | not ready / not ready | refused, 125 | refused, 125 |
| ubuntu-24.04-arm | 3 + AppArmor profile | 0.11.1 | ok | ready / ready | settled, 0 | settled, 0, HTTP 200 |
| ubuntu-24.04-arm | 4 + sysctl | 0.11.1 | ok | ready / ready | settled, 0 | settled, 0, HTTP 200 |
| ubuntu-22.04 | all | 0.6.1, then 0.11.1 | ok | — | — | — |

- **Why stock fails, twice over.** apt's bubblewrap is 0.9.0, older than the
  0.10.0 the jail requires (`bwrap_too_old`), and the image restricts
  unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns
  = 1`; `unshare -Ur` fails too). With 0.11.1 the version is fine, but the
  restriction still denies the uid map: `doctor` reports `tree_termination`
  unprovable and a run refuses `missing_capability` before exec. No `bwrap`
  is preinstalled.
- **Variant 3, the narrow change.** Receipts: both runs `settled`, `tree_empty`
  true, integrity `verified`; the `tool` run with five classes active
  (`proxy.net` unsupported, as for every proxy-less `tool` run), the `agent`
  run with all six active and no gaps. The `agent` summary: `network: allowed
  api.github.com:443 (1)`. `doctor` reports unavailable only
  `agent_inner_sandbox` (`inner_sandbox_unproven`), `gpu_passthrough` and
  `storage_ceiling` (`no_user_hard_quota`), and the restriction itself as on
  (`apparmor_userns_restriction: available`, `restriction_on`): the receipt
  says the host restricts user namespaces and that this binary was let
  through. Unlike the reference host, `nested_user_namespace` is available,
  since the profile is unconfined.
- **Variant 4** gives the same results, with `apparmor_userns_restriction`
  unavailable (`restriction_off`): the whole runner lost the restriction, not
  one binary.
- **The rest of the host suits the jail.** cgroup v2 with every controller,
  the runner account's systemd user manager running and lingering (the scope
  step), `ptrace_scope` 1, 4 CPUs on x86_64.
- **ubuntu-22.04** never got a `ukai-jail`: the installer refused before any
  download, `glibc 2.35 is too old; this preview requires glibc 2.39 or newer`.
  Its rows have probes only.
- **Cost.** The whole job, including the apt build dependencies, the
  bubblewrap build and all four variants, took 22 to 31 seconds per image.

## What this does and does not establish

It establishes that the jail's contained profiles work on the two hosted
24.04 images once a recent bubblewrap may create a user namespace, with no
other host change. It does not establish a compatibility claim: one run per
variant, no real agent, no credential through the vault, no long workload,
and the evidence classes were checked on two tiny commands. `ubuntu-latest`
was not probed separately (it names 24.04 today). Larger runners, self-hosted
runners and other CI providers are not covered.

Both working variants change the runner, which the jail never does on an
operator's host (jail-v1 §3, "no host configuration"). On a disposable runner
the workflow owns, a one-binary profile is the narrower of the two: it lets
that `bwrap` through and leaves the restriction in force for every other
program, and `doctor` and the receipt still report it on. Whether an Action
may make that change, disclosed in its output, is an operator decision.
