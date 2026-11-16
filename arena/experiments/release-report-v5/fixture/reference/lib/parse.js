// Parse and normalize change records. Reference repair, used for calibration
// only: it is never placed in an agent workspace.
const TYPES = new Set(['added', 'changed', 'fixed', 'removed']);
const parts = (version) => String(version).split('.').map((x) => parseInt(x, 10) || 0);
// Numeric, part by part; a missing part counts as 0. `2.10.0` is above `2.9.0`.
function compareVersions(a, b) {
  const ka = parts(a), kb = parts(b);
  for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
    const difference = (ka[i] || 0) - (kb[i] || 0);
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return 0;
}
function parseRecords(raw) {
  const list = JSON.parse(raw);
  if (!Array.isArray(list)) throw new Error('input must be an array');
  const byId = new Map();
  for (const r of list) {
    if (!r.id || !r.type || !r.version || !r.text) throw new Error('missing fields');
    if (!TYPES.has(r.type)) throw new Error('unsupported type: ' + r.type);
    const record = { id: r.id, type: r.type, version: r.version, text: r.text };
    // A Map keeps the position of the first insertion when a key is set again.
    if (!byId.has(r.id) || compareVersions(record.version, byId.get(r.id).version) > 0)
      byId.set(r.id, record);
  }
  return [...byId.values()];
}
module.exports = { parseRecords };
