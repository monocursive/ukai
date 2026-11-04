# macOS native workflow scratch files — 2026-11-02

**No measurement.** This directory holds three files that were found
untracked in the main checkout on 2026-11-03 and committed byte for byte
(fix wave 1103, decision D12). Nothing in the repository cites them, and
no command line, build output, result or provenance record was kept with
them. They establish nothing about any acceptance row.

| File | What it is |
| --- | --- |
| [harness/bootstrap_exec.c](harness/bootstrap_exec.c) | A 20-line C program. It exits 77 unless `hw.model` is `VirtualMac2,1` (a macOS guest VM). Given `null` or `dead`, it sets its own task's bootstrap port to `MACH_PORT_NULL` or to a port whose receive right it has just dropped (`task_set_bootstrap_port`), then `execv`s the remaining arguments. Exit codes 64–69 name its failure points. |
| [harness/launchd_client.c](harness/launchd_client.c) | A 21-line C program with the same `VirtualMac2,1` guard. It sends launchd a `StartJob` request (`launch_msg`) for one job label, accepted only with the prefix `com.ukai.protocol.`, and prints the reply's type and errno; it runs no `launchctl`. |
| [vm-run.log](vm-run.log) | 38 bytes, one line: `guest has stopped the virtual machine`. Which run wrote it is not recorded. |

The files' modification times in the main checkout were 2026-11-02 10:01
(both sources) and 11:17 (the log), local time. Their subject, the inherited
bootstrap port and launchd's job protocol, is the one the
[bootstrap-strip record](../macos-k90-bootstrap-strip-2026-11-02/README.md)
measured on the same day; whether they fed that record is not recorded.
