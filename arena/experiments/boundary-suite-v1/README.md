# Boundary suite v1

Frozen protocol family `arena.boundary-suite.protocol/1`, experiment class
`boundary_enforcement`. Thirteen fixed synthetic cases; see
[protocol.json](protocol.json) for the exact matrix, limits and expected
observations. Implemented by [../boundary_suite.py](../boundary_suite.py).

| Group | Cases | Question |
| --- | --- | --- |
| NET | NET-A / NET-D | One fixed curl upload with the collector granted / absent |
| CHILD | CHILD-A / CHILD-D | The same upload launched by the frozen `parent.py` as its single child |
| READ | READ-A / READ-D | Fixed hash command reads a disposable protected file with / without an exact read grant |
| WRITE | WRITE-A / WRITE-D | Fixed marker write under a read-write / read-only grant for that path |
| TIME | TIME-A / TIME-D | Frozen `sleeper.py` (one child) finishing inside a 2s wall deadline / stopped by it |
| DEP | DEP-C / DEP-A / DEP-D | Clean local install; malicious install with the collector granted / absent |

Doctor, node/npm version probes and checker calibrations are additional
executions, recorded separately in the qualification record — never inside the
thirteen-case count. Ordinary cases use wall=30s, pids=32, mem=256MiB;
dependency controls keep the already qualified 1GiB ceiling; the time cases
pin the 2s deadline, 1s/10s durations and one-child program in the protocol.

Result model: every case produces the explicit §8 field set (operation, policy,
enforcement, effect with separate `violation_confirmed`, utility, attribution
`fixed_control`, quality, cost, lifecycle). Classification follows the frozen
rules: `request_observed_with_denial`, `specified_read_failed`,
`specified_write_prevented`, `deadline_enforced_and_tree_settled`,
`clean_install_no_collector_traffic`, `forbidden_effect_confirmed`,
`effect_observed_policy_unverified`, `inconclusive`, `protocol_deviation`.
`policy_read_denials` stays `null`; generic errno values never become
authoritative Ukai decisions; a controller timeout alone can never pass TIME-D.

## Commands

```sh
# Offline static preparation (no process, socket, credential or budget access)
PYTHONPATH=arena python3 -B -m experiments.boundary_suite prepare --out NEW_DIR

# Unpaid Linux qualification of the thirteen fixed cases (owned collector only)
PYTHONPATH=arena python3 -B -m experiments.boundary_suite qualify \
  --config PRIVATE_LINUX_CONFIG --out NEW_DIR

# Offline replay of one captured case into a new output directory
PYTHONPATH=arena python3 -B -m experiments.boundary_suite score \
  --input SAVED_CASE_RUN --out NEW_DIR
```

The suite never launches a model, reads provider credentials, or mutates any
budget. Network cases require the owned live collector endpoint;
documentation-only, loopback or invalid addresses cannot substitute for
delivery and authoritative denial evidence.
