# Try the permission boundary

This lab executes thirteen fixed controls on an owned Linux x86-64 worker.
It uses synthetic tokens and a collector on that same worker. It launches no
model, uses no API key, and makes no package-registry requests during the cases.
It is the existing boundary-suite v1, with a smaller configuration entrypoint.

## What you will learn

Compare NET-A/D and DEP-A/D: the same specified upload is delivered when its
destination is granted and denied when it is absent. Allowing the destination
is an expected delivery, not a sandbox escape. An allowlist does not classify
payloads or distinguish safe and destructive actions at a permitted service.

READ-A/D compare an exact read grant with no grant. WRITE-A/D compare a writable
file with a read-only file. The file observations cover these commands under
verified mounts, not every possible filesystem attack. CHILD-A/D exercise a
scripted child upload. TIME-A/D exercise completion before a deadline and a
deliberate wall-limit hit. DEP-C checks that the clean install produces no
collector traffic. Install completion is checked, not agent productivity.

## Requirements

- An owned, disposable Linux x86-64 worker with bubblewrap and an Ukai-ready
  agent profile (`ukai doctor --profile agent --workspace OWNED_EMPTY_DIR --json`).
- Python 3.10+, `/usr/bin/curl`, and `/usr/bin/python3`.
- The pinned Ukai Linux rc.5, Node 22.22.3 and npm 11.17.0 files. Pins are in
  `source/reader_lab.py`; mismatches stop before the cases. This is a reproduction
  of that build, not a test of whatever version happens to be installed.
- The worker's own public IPv4 address, bindable on that worker and reachable
  from it on the collector's ephemeral TCP port. The collector serves only
  synthetic test data. Do not point this option at someone else's machine.

Ukai release: https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.5

Node distribution: https://nodejs.org/dist/v22.22.3/

npm distribution: https://registry.npmjs.org/npm/-/npm-11.17.0.tgz

Install the tools before running the lab. The lab does not download or upgrade
them, change your firewall, install services, or configure credentials.

## Run

Unzip the reader-lab package. Replace the paths and owned address below. Outputs
must be fresh paths outside `source/`; an existing result is never overwritten.

```sh
python3 -B source/reader_lab.py configure \
  --jail /absolute/path/to/ukai \
  --node /absolute/path/to/node \
  --npm /absolute/path/to/npm/package/bin/npm-cli.js \
  --npm-root /absolute/path/to/npm/package \
  --collector-ip YOUR_WORKER_PUBLIC_IPV4 \
  --out ./lab-config.json

python3 -B source/reader_lab.py run \
  --config ./lab-config.json --out ./lab-results
```

Inspect `lab-results/results.md`, `qualification.json`, per-case `scores/`, and
the raw receipts, proxy events and collector observations under `runs/`.
Doctor and runtime-version checks are listed separately from the thirteen cases.
The runner closes the collector and checks Ukai settlement; result files remain
for inspection. A nonzero exit or missing observation is not a successful denial.

## Verify the download or replay an observation

Run `python3 -B verify.py` from the extracted package to verify file integrity.
This check does not execute the lab and does not contact a provider.

To rescore a newly captured case without another execution:

```sh
PYTHONPATH=source python3 -B -m experiments.boundary_suite score \
  --input ./lab-results/runs/CASE_ID --out ./rescored-CASE_ID
```

The separate historical evidence download contains redacted observations and
its own verifier. That public verifier checks curated consistency claims; full
historical containment scoring needs the private originals. A fresh lab run
creates your own complete local evidence and is a new scripted run, not a
reproduction of the agent's decisions or a new agent sample.
