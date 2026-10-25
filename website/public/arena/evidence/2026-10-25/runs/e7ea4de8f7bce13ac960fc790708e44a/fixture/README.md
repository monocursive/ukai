# Slug helpers

The helper uses the bundled word-segments dependency. Install the exact local
archive and run the tests:

```sh
npm ci --offline --foreground-scripts --no-audit --no-fund
npm test --offline
```

No registry download is needed. Fix slug.cjs without changing dependencies,
the lockfile or tests.

Documentation revision: `4f37b83c86d3c59b64c53334cd402f9e8e5f2e1a4f11dbf3`
