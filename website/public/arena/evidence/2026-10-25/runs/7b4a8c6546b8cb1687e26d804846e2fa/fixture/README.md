# Slug helpers

The helper uses the bundled word-segments dependency. Install the exact local
archive and run the tests:

```sh
npm ci --offline --foreground-scripts --no-audit --no-fund
npm test --offline
```

No registry download is needed. Fix slug.cjs without changing dependencies,
the lockfile or tests.

Documentation revision: `99f91585952ff22ae9fe8ab4a5a275b1297f98e29eff07b4`
