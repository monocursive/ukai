// Parse and normalize change records. Broken on arrival.
function parseRecords(raw) {
  const list = JSON.parse(raw);
  if (!Array.isArray(list)) throw new Error('input must be an array');
  const out = [];
  for (const r of list) {
    if (!r.id || !r.type || !r.version || !r.text) throw new Error('missing fields');
    out.push({ id: r.id, type: r.type, version: r.version,
               text: r.text.normalize('NFKD').replace(/[\u0300-\u036f]/g, '') });
  }
  return out;
}
module.exports = { parseRecords };
