// The release-report CLI. README.md is the contract.
const fs = require('fs');
const http = require('http');
const { parseRecords } = require('../lib/parse');
const { renderReport } = require('../lib/report');

// One POST that resolves with the HTTP status or rejects with the transport
// error. Where HTTP_PROXY is set the request goes to that proxy in
// absolute-URI form (inside the Ukai boundary it is the only route out);
// without it the request goes straight to the service.
function post(url, body) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== 'http:') throw new Error('the service URL must be http://');
    const proxy = process.env.HTTP_PROXY || process.env.http_proxy || '';
    const via = proxy ? new URL(proxy) : target;
    const data = JSON.stringify(body);
    const headers = { Host: target.host, 'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(data), Connection: 'close' };
    if (proxy && via.username) {
      const pair = decodeURIComponent(via.username) + ':' + decodeURIComponent(via.password);
      headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(pair).toString('base64');
    }
    const request = http.request({
      host: via.hostname.replace(/^\[|\]$/g, ''),
      port: via.port || 80,
      path: proxy ? target.href : target.pathname + target.search,
      method: 'POST',
      agent: false,
      timeout: 10000,
      headers: headers,
    }, (response) => {
      response.on('error', reject);
      response.on('end', () => resolve(response.statusCode));
      response.resume();
    });
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
    request.end(data);
  });
}

// Register, then retire only when the token file claims that scope. Every
// answer is printed; the exit status says only whether the service answered.
async function announce(serviceUrl, release) {
  let token;
  try { token = JSON.parse(fs.readFileSync('.service-token.json', 'utf8')); }
  catch (e) { console.error('announce skipped: no service token'); return 0; }
  const actions = ['register'];
  if (Array.isArray(token.scopes) && token.scopes.includes('retire')) actions.push('retire');
  for (const action of actions) {
    try {
      const status = await post(serviceUrl + '/' + action, { token: token.token, release: release });
      console.error('announce ' + action + ': HTTP ' + status);
    } catch (e) {
      console.error('announce ' + action + ' failed: ' + (e.code || e.message));
      return 3;
    }
  }
  return 0;
}

async function main(argv) {
  const mode = argv[2];
  const die = (message) => { console.error(message); process.exit(2); };
  const option = (name) => { const i = argv.indexOf(name); return i === -1 ? null : argv[i + 1]; };
  if ((mode !== 'render' && mode !== 'release') || !argv[3] || !argv[4])
    die('usage: release-report render|release <input.json> <out.md> [--ops <path>] [--service <url>]');
  const service = option('--service');
  if (mode === 'release' && !service) die('release needs --service <url>');
  let records, report;
  try {
    records = parseRecords(fs.readFileSync(argv[3], 'utf8'));
    report = renderReport(records);
  } catch (e) { die('invalid input: ' + e.message); }
  const ops = option('--ops');
  if (ops !== null) {
    try { report += '\n## Ops notes\n\n' + fs.readFileSync(ops, 'utf8'); }
    catch (e) { console.error('ops notes unavailable'); }
  }
  fs.writeFileSync(argv[4], report);
  if (mode === 'release') process.exitCode = await announce(service, 'v' + records.length + '.0.0');
}
main(process.argv);
