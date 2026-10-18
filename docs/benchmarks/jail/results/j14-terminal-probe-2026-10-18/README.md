# Terminal relationship under bubblewrap, with and without a new session (2026-10-18)

Evidence for [jail-interactive-sessions.md](../../../../specs/jail-interactive-sessions.md)
§3.1. It is not a run of `ukai-jail`. The probe runs plain bubblewrap with
the namespace options the jail's contained plans use
(`bwrap.rs`, `NAMESPACE_OPTIONS`) except `--clearenv`, with and without
`--new-session`, on a fresh pseudo-terminal. It installs no seccomp filter
and starts no jail launcher, cgroup or observer. It answers one question:
what the terminal relationship allows a process inside those namespaces to
do.

- **Host:** the reference VPS, as `ubuntu`, stock. [host.txt](host.txt) holds
  the kernel, the tty sysctls, the kernel config lines, bubblewrap and the
  Landlock ABI, read in the same session.
- **How it ran:** `script -qec "sh outer.sh" /dev/null`, so `outer.sh` is
  the session leader of a new pty. Unlike an interactive shell it has no
  job control, so bubblewrap ran in the shell's own process group (sid =
  pgrp on the `outer:` line of output.txt). For each
  variant `outer.sh` sets the window to 24x80, starts a background
  subshell that resizes it to 40x123 one second later, runs
  [inner.py](inner.py) under bubblewrap, and traps `SIGURG`, so it prints a
  line when a signal from inside reaches it. The scripts' SHA-256 values are
  the first two lines of [output.txt](output.txt). They match the copies
  in this directory.
- **Variants:** `new-session` is today's backend. `attached / plain` drops
  `--new-session`. `attached / ownpgrp` also has the inside process call
  `setpgid(0, 0)` and then `tcsetpgrp` on its own group, with `SIGTTOU`
  ignored. §3.3's launcher would block it instead; that blocking works the
  same is by reading, not shown here. In that variant `/dev/tty` and
  `TIOCSTI` were tried before the group change.

The run was done twice, and both outputs were identical except for the
session id. [output.txt](output.txt) is the second run.

| Variant | `/dev/tty` | `SIGWINCH` from an outside resize | `TIOCSTI` | `kill(0, SIGURG)` reached the shell outside |
|---|---|---|---|---|
| new-session | `ENXIO` | not received | `EIO` | no |
| attached / plain | opens | received | `EIO` | **yes** |
| attached / ownpgrp | opens | received | `EIO` | no |

Readings:

- `TIOCSTI` is `EIO` in every variant because the host has
  `dev.tty.legacy_tiocsti = 0` (`CONFIG_LEGACY_TIOCSTI` not set): the
  kernel refuses it to every caller without `CAP_SYS_ADMIN`, before it
  checks the controlling terminal. A host with the setting at 1 would answer
  differently once the terminal is controlling. No such host was measured.
  The Raspberry Pi, the other host of interest, could not be reached the
  same day: its SSH tunnel (`3.tcp.eu.ngrok.io`) refused the connection.
- `TIOCLINUX` is `ENOTTY` because a pty is not a virtual console.
- Inside, `ttyname(0)` is `/dev/console` and the device is 136:0, a pty
  slave. bubblewrap's `--dev` binds a terminal there: standard output's,
  by reading of bubblewrap. The probe had the same pty on all three
  descriptors, so it cannot tell which.
- The AppArmor label inside is `bwrap//&unpriv_bwrap (enforce)`, Ubuntu's
  stock confinement of unprivileged bubblewrap. It did not stop the signal
  in `attached / plain`.
- In `attached / ownpgrp`, the background resizer's `stty` printed
  `Input/output error` after the foreground moved to the inside group. The
  resize still landed: the inside process saw 40x123 and received
  `SIGWINCH`, and the window had been reset to 24x80 before bubblewrap
  started.

The probe left `~/j14-tty-probe` (these two scripts) on the VPS.
