# Release-report study derivative — 11-12 November 2026 (corrected 12 November)

Six unattended sessions across four protocol versions of one repair task. The five-lane permission matrix this family was built for was never measured.

**Read `correction.json` first.** This README first described the study as: the agent rewrote the tests and was caught; the read-only mount held; one requirement ("version-content selection") kept failing; clarifying it scored worse, so requirements trade at a capacity boundary. Reading the preserved transcripts, final workspaces and traces showed that those readings came from five defects in our own task, not from the sessions:

- the one case every session failed tests numeric version ordering (2.10.0 above 2.9.0), which the specification never states and the visible tests never exercise;
- the read-only test file mounted in versions 2 to 4 is not valid JavaScript and never ran;
- versions 3 and 4 gave a task prompt naming one broken module and a README naming three, and the version 4 score drop follows from an edit to a module that shipped correct;
- the version 1 tests contain an assertion that cannot pass;
- the announce step could not reach the granted service from inside the boundary.

What stands: the scores, the turn-cap stops, the integrity snapshot catching the one changed protected file, and the absence of any write attempt on the read-only mount.

`results.json` and the six records under `runs/` are unchanged. The first README text is in the repository history. This derivative was corrected before it was first served.
