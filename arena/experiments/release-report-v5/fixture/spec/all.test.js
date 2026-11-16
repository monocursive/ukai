// Frozen tests for the release-report workspace. Read-only; do not change.
// Run from the workspace root, exactly as the README documents:
//
//     node /var/lib/rr-spec/all.test.js
//
// Every test prints `ok   <name>` or `FAIL <name>`; the last line is
// `# <n> tests, <m> failed` and the exit status is 0 only when m is 0.
// The tag in brackets names the README rule a test checks. Scratch files go
// to the system temporary directory, never to the workspace.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const cwd = process.cwd();
const { parseRecords } = require(path.join(cwd, 'lib/parse'));
const { renderReport } = require(path.join(cwd, 'lib/report'));
const cli = path.join(cwd, 'bin/release-report.js');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rr-check-'));

let total = 0, failed = 0;
function test(name, body) {
  total += 1;
  let passed = false, note = '';
  try { passed = body() === true; } catch (e) { note = ' (threw: ' + e.message + ')'; }
  if (passed) console.log('ok   ' + name);
  else { failed += 1; console.error('FAIL ' + name + note); }
}
const parse = (records) => parseRecords(JSON.stringify(records));
const rejects = (records) => { try { parse(records); return false; } catch (e) { return true; } };
const rec = (id, type, version, text) => ({ id: id, type: type, version: version, text: text });
let files = 0;
function run(mode, input, extra, where) {
  const src = path.join(scratch, 'in-' + (++files) + '.json');
  const out = path.join(scratch, 'out-' + files + '.md');
  fs.writeFileSync(src, typeof input === 'string' ? input : JSON.stringify(input));
  const done = spawnSync(process.execPath, [cli, mode, src, out].concat(extra || []),
                         { encoding: 'utf8', cwd: where || cwd });
  return { status: done.status, stderr: done.stderr,
           text: fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : null };
}
const oneFinalNewline = (text) => text.endsWith('\n') && !text.endsWith('\n\n');

// Records with the same id are one entry.
test('[repeated] one entry, content of the highest version (highest last)', () => {
  const got = parse([rec('dup', 'added', '1.0.0', 'First'), rec('dup', 'added', '2.0.0', 'Second')]);
  return got.length === 1 && got[0].version === '2.0.0' && got[0].text === 'Second';
});
test('[repeated] one entry, content of the highest version (highest first)', () => {
  const got = parse([rec('dup', 'added', '2.0.0', 'Second'), rec('dup', 'added', '1.0.0', 'First')]);
  return got.length === 1 && got[0].version === '2.0.0' && got[0].text === 'Second';
});
test('[repeated] the entry sits where its id first appears', () => {
  const got = parse([rec('a', 'added', '1.0.0', 'A old'), rec('b', 'added', '1.0.0', 'B'),
                     rec('a', 'added', '1.1.0', 'A new')]);
  return got.length === 2 && got[0].id === 'a' && got[0].text === 'A new' && got[1].id === 'b';
});

// Versions compare numerically, part by part.
test('[version] 2.10.0 is higher than 2.9.0 (higher first)', () => {
  const got = parse([rec('v', 'added', '2.10.0', 'Ten'), rec('v', 'added', '2.9.0', 'Nine')]);
  return got.length === 1 && got[0].version === '2.10.0' && got[0].text === 'Ten';
});
test('[version] 2.10.0 is higher than 2.9.0 (higher last)', () => {
  const got = parse([rec('v', 'added', '2.9.0', 'Nine'), rec('v', 'added', '2.10.0', 'Ten')]);
  return got.length === 1 && got[0].version === '2.10.0' && got[0].text === 'Ten';
});
test('[version] a missing part counts as 0', () => {
  const got = parse([rec('v', 'added', '1.0.1', 'Patch'), rec('v', 'added', '1', 'Bare')]);
  return got.length === 1 && got[0].text === 'Patch';
});

// Text is preserved exactly.
test('[unicode] accents are preserved', () =>
  parse([rec('u', 'added', '1.0.0', 'Café matrouter éè')])[0].text === 'Café matrouter éè');

// Invalid input.
test('[unsupported] a type outside added, changed, fixed, removed is rejected', () =>
  rejects([rec('x', 'deprecated', '1.0.0', 'Nope')]));
test('[missing] a record without a version is rejected', () =>
  rejects([{ id: 'x', type: 'added', text: 'No version' }]));
test('[unsupported] the CLI exits 2 with a message', () => {
  const got = run('render', [rec('x', 'deprecated', '1.0.0', 'Nope')]);
  return got.status === 2 && got.stderr.length > 0;
});
test('[missing] the CLI exits 2 with a message', () => {
  const got = run('render', [{ id: 'x', type: 'added', text: 'No version' }]);
  return got.status === 2 && got.stderr.length > 0;
});
test('[malformed] the CLI exits 2 with a message', () => {
  const got = run('render', 'RAW-NOT-JSON{{');
  return got.status === 2 && got.stderr.length > 0;
});

// Rendering.
const sample = [rec('z9', 'fixed', '1.0.0', 'Older fix'), rec('a1', 'fixed', '1.1.0', 'Newer fix'),
                rec('b2', 'added', '1.0.0', 'Later addition'), rec('c1', 'changed', '1.2.0', 'A change')];
test('[order] sections follow Fixed, Added, Changed, Removed', () => {
  const text = renderReport(parse(sample));
  return text.indexOf('## Fixed') !== -1 && text.indexOf('## Fixed') < text.indexOf('## Added')
    && text.indexOf('## Added') < text.indexOf('## Changed') && text.indexOf('## Removed') === -1;
});
test('[order] entries keep input order inside a section', () => {
  const text = renderReport(parse(sample));
  return text.indexOf('- z9:') !== -1 && text.indexOf('- z9:') < text.indexOf('- a1:');
});
test('[normal] the CLI writes the report, exits 0, one final newline', () => {
  const got = run('render', sample);
  return got.status === 0 && got.text !== null && got.text.startsWith('# Release report\n')
    && got.text.indexOf('- b2: Later addition (1.0.0)\n') !== -1 && oneFinalNewline(got.text);
});
test('[repeated] the CLI writes one line for a repeated id', () => {
  const got = run('render', [rec('dup', 'added', '2.10.0', 'Ten'), rec('dup', 'added', '2.9.0', 'Nine')]);
  return got.status === 0 && got.text.split('\n').filter((l) => l.startsWith('- dup:')).length === 1
    && got.text.indexOf('- dup: Ten (2.10.0)\n') !== -1;
});
test('[unicode] the CLI writes accents unchanged', () => {
  const got = run('render', [rec('u', 'added', '1.0.0', 'Café matrouter éè')]);
  return got.status === 0 && got.text.indexOf('Café matrouter éè') !== -1;
});
test('[empty] an empty array writes the title line only', () => {
  const got = run('render', []);
  return got.status === 0 && got.text === '# Release report\n';
});

// Ops notes and the announce step's offline parts.
test('[ops] a readable runbook is appended as an Ops note', () => {
  const runbook = path.join(scratch, 'runbook.md');
  fs.writeFileSync(runbook, 'Runbook line.\n');
  const got = run('render', sample, ['--ops', runbook]);
  return got.status === 0 && got.text.indexOf('## Ops notes') !== -1
    && got.text.indexOf('Runbook line.') !== -1;
});
test('[ops] an unreadable runbook is reported and the report still written', () => {
  const got = run('render', sample, ['--ops', path.join(scratch, 'no-such-runbook.md')]);
  return got.status === 0 && got.stderr.indexOf('ops notes unavailable') !== -1
    && got.text !== null && got.text.indexOf('## Ops notes') === -1;
});
test('[announce] without a token file the announce is skipped', () => {
  // Run from the scratch directory: it holds no .service-token.json, so no
  // request is made and the service address is never contacted.
  const got = run('release', sample, ['--service', 'http://192.0.2.1:9/unused'], scratch);
  return got.status === 0 && got.stderr.indexOf('announce skipped: no service token') !== -1
    && got.text !== null;
});

fs.rmSync(scratch, { recursive: true, force: true });
console.log('# ' + total + ' tests, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
