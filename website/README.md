# Ukai website

The Astro site for [Ukai](https://ukai.sh), covering the standalone Linux
jail and the separate macOS VM preview.

```sh
cd website
npm ci
npm run dev
npm run build
```

The homepage is `src/pages/index.astro`. The guide and roadmap render the
repository's `docs/guide.md` and `docs/roadmap.md` directly, so those documents
have one source. The cormorant branding lives in `../assets/logo/`; run
`uv run ../assets/logo/export_assets.py` from this directory to regenerate
the website assets and favicons. Fonts are hosted locally. Current source links
and clone instructions target `dev`; published release links retain their
immutable tags.

`/install.sh` and `/release.pub` are the repository's root `install.sh` and
`crates/ukai-jail/dist/release.pub`, imported at build time, so the served
installer cannot drift from the reviewed one. Release links and versions come
from `crates/ukai-jail/dist/release.json`. Its `published_tag` fields retain
the immutable tags of the previews released before the rename; `tag_prefix`
is for newly assembled Ukai releases. Update `published_tag` when publishing.

The documentation layout generates its section index from Markdown headings.
`/guide.md` and `/roadmap.md` serve the exact source text. `/llms.txt` is a
short discovery index following the [llms.txt proposal](https://llmstxt.org/),
and `/llms-full.txt` combines the index and both documents for a single fetch.
These are static build outputs, with no API service or separate content copy.
The page toolbar lets readers open Markdown or copy its URL for an agent;
automatic discovery of `llms.txt` is not assumed.

After editing shared files under `docs/`, restart the development server if
its Markdown cache is stale. `npm run build` regenerates all formats.

The Cloudflare Pages project `ukai` serves `https://ukai.sh`. `npm run
deploy` publishes the built site and must only be used when publication is
requested. Local builds do not update the live website.

Keep current features, experiments, and plans distinct. Link support and
performance claims to the exact recorded builds; never use the archived
runtime's releases as the jail installer.

## Arena field notes

The Arena navigation now opens `/arena/field-notes/`, a reader index.
`/arena/field-notes/dependency-install/` presents the measured 26 October
workflows with separate task/effect observations and practical permission
lessons. `src/arena_readers.ts` checks those statements against the preserved
public export at build time. `/arena/method/` explains evidence levels and
links the credential-free reader lab. The reader program and next study
protocol are in `../docs/arena-reader-program.md`.

Field note 003 (`/arena/field-notes/twin-exposure/`) presents the complete
1 November pair. Field note 004 (`/arena/field-notes/incident-replay/`) preserves
the stopped adaptation and its unclaimed bare slot. `src/arena_november.ts`
checks their claims against the new public derivative. Its 24 records are
19 new scripted controls and five outer agent sessions. The nested log has no
terminal result; its nine API retry events are described separately.

`arena/export_reader_results.py --frozen-arena <original-arena-source>` verifies
the saved source against both original contracts before replaying their scores.
This keeps a later parser repair from rewriting the stopped result. The
separate parser diagnostic records the repair's limited effect.

`public/arena/evidence/2026-11-01-parser-diagnostic.json` has no generator in
this repository: a one-off script wrote it during the 1 November closeout, and
the private copy `evidence/arena-reader-2026-11-01/parser-diagnostic.json` is
byte-identical. It summarizes the saved outer transcript and nested log of
replay run `sg-fc243e25…` under the repaired adapter `claude/2`
(`adapter_sha256` is `arena/m1/adapters.py` as of 1 November): gaps, tool
calls, usage records and API retry events. Re-reading the private bundle with
`m1.adapters.normalize` reproduces the gap, call and usage counts; the nine
retry events are the nested log's `system`/`api_retry` rows.
`original_verdict_preserved: null`
is not a yes/no answer. Its value matches the original score's `terminal`,
which is null because that score reached no verdict (labels `inconclusive`).
The original score is unchanged; the run record's `original_score_sha256`
identifies it. `src/arena_november.ts` pins every one of these values. The file
is published as written and is never edited.

Build the lab archive with `python3 -B arena/package_reader_lab.py --out
website/public/arena/downloads/ukai-arena-reader-lab-2026-11-01.zip` from the
repository root. The packager refuses to overwrite an archive; publish a new
edition for source changes after release. Its explicit source allowlist never
packages private evidence or account configuration. The README inside describes
the pinned Linux dependencies and the thirteen-case unpaid run.

`/arena/` is an illustrated field note in nine chapters (how agents work, the
traps, what to measure, the sandbox, controls, the day's episodes, results, the
26 October boundary evaluation, lessons), followed by a board of all 25 October
runs. `/arena/runs/[id]/` renders each of the 34 preserved 25 October records,
with original and offline scores separated. Those pages read **only** the
redacted export under `public/arena/evidence/2026-10-25/`; never point the
website at private Arena bundles or account files. Transcript and fixture text
is escaped as text.

The 26 October chapter reads the separate export under
`public/arena/evidence/2026-10-26-workflow-v2/` through `src/arena_boundary.ts`,
and `/arena/boundary/[id]/` renders each of its 22 records. `boundaryMust()`
checks fail the build the same way. `public/arena/evidence/2026-10-26/` is the
earlier 17-record boundary export, kept unchanged next to its archive.

Quotes, tool-call strips, counts and fixture excerpts are read from the export
at build time. `must()` checks in `src/pages/arena/index.astro` and `quote()` in
`src/arena.ts` fail the build if the export stops supporting a claim the story
makes. Animations are CSS or SVG, start on scroll, and stop under reduced motion;
without JavaScript every section, and every quiz answer, is visible.

The 25 October ZIP under `public/arena/downloads/` is the unchanged preparation
snapshot (SHA-256 starts `8d3eb857`). Its historical unpublished label remains
intact. `public/arena/publication.json` describes the later website publication.
Its top-level fields are the original 25 October record; each later archive gets
an additive entry under `later_publications` when it is first served.
From 3 November the shared exporter archive stamps entries with the export's own
date; the 26 October and 1 November evidence zips keep their 26 October stamps
and are never regenerated.
Preserve this evidence edition when adding future field notes; use a new version
directory and archive for a new export.

Run `npm run build` from this package before deployment. Verify the archive with
the packaged `verify.py` and exposure replay, inspect the run filters and score
disclosures on desktop and mobile, and check the served ZIP hash after deployment.
The fixture/exposure checks do not launch agents or contact a paid model provider.
