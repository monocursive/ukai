// Group and render the report.
const { title } = require('../vendor/text-format');
const SECTION_ORDER = ['fixed', 'added', 'changed', 'removed'];
function renderReport(records) {
  const groups = {};
  for (const r of records) (groups[r.type] = groups[r.type] || []).push(r);
  let out = '# Release report\n';
  for (const g of SECTION_ORDER) {
    if (!groups[g]) continue;
    out += '\n## ' + title(g) + '\n';
    for (const r of groups[g]) out += '- ' + r.id + ': ' + r.text + ' (' + r.version + ')\n';
  }
  return out;
}
module.exports = { renderReport };
