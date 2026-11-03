# How far a non-root process can raise RLIMIT_NPROC — 2026-11-03

**Development evidence only. No gate is promoted.** One run of
[measure.sh](measure.sh) on the development Mac (macOS 27.0.1, build
`26A434`, arm64, uid 501), outside any sandbox and outside `ukai-jail`;
output verbatim in [output.txt](output.txt). It answers one question that
decision D13 (fix wave 1103, jail-macos §4.1 rule 6) raised: before D13
the clamped path lowered nothing, so what could a member gain by raising
its own soft limit?

Host: `kern.maxproc` 16000, `kern.maxprocperuid` 10666; the shell inherited
soft 10666, hard 16000.

| Shape | Result |
| --- | --- |
| Inherited 10666/16000; raise soft to 12000 | succeeds, but soft stays 10666 and hard now reads 10666 |
| Inherited 10666/16000; raise soft to 16000 | `EINVAL` |
| Soft lowered to 5000; a child raises it to 10666 | succeeds (soft 10666) |
| Soft lowered to 5000; a child raises it to 12000 | `EINVAL` |
| Soft 5000, hard 8000; a child raises to 8000 / 9000 | succeeds / `EINVAL` |
| `setrlimit(5000, 16000)` from Python | reads back `(5000, 10666)` |

So on this host every non-root `setrlimit(RLIMIT_NPROC)` leaves both values
at most `kern.maxprocperuid`, and a member can raise its soft limit up to
min(hard, `kern.maxprocperuid`), never to a higher raw hard limit.

What this means for the pre-D13 clamped path, which set no limit:

- Where the inherited soft limit already equals `kern.maxprocperuid`
  (this Mac's default; and, by its recorded values, the [2026-11-02
  compatibility VM](../macos-compat-2026-11-02/README.md)'s clamped row:
  `kern.maxprocperuid` 1333 for that measurement, soft 1333 and hard 2000
  in its final guest state), raising gained a member nothing.
- Where the operator's soft limit sits below `kern.maxprocperuid` (for
  example after `ulimit -Su`), a member could raise it back up to
  `kern.maxprocperuid`, past the ceiling the receipt reported. That is the
  shape D13's fix closes: both limits are now lowered to the ceiling.

Not measured: the same calls inside the Seatbelt profile, other macOS
releases, and the VM itself (the VM statement above is inferred from this
host's behaviour and the VM's recorded values).
