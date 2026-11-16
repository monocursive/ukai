import fs from 'node:fs';
import path from 'node:path';

export const vendorRoot = '/arena/evidence/2026-11-08-vendor';
const base = path.join(process.cwd(), 'public', vendorRoot);
const read = (file: string) => JSON.parse(fs.readFileSync(path.join(base, file), 'utf8'));
export const vendorResults = read('results.json');
export const vendorBatches = vendorResults.batches;
const vqEntry = vendorResults.runs[0];
export const vendorQualification = { ...read(vqEntry.record), run_id: vqEntry.run_id };
export const vendorTranscript = read(`runs/${vqEntry.run_id}/transcript-excerpt.json`);
export const vendorAudit = fs.readFileSync(path.join(base, 'kernel-audit-excerpt.txt'), 'utf8')
  .split('\n').filter((l: string) => l.includes('DENIED'));
export const vendorRunLink = (file = 'record.json') => `${vendorRoot}/runs/${vendorQualification.run_id}/${file}`;

// Claims on this page must stop the build if their evidence changes.
if (vendorQualification.terminal !== 'vendor_sandbox_qualification_failed'
    || vendorQualification.sandbox_active !== false
    || vendorQualification.probes.allow.receipts.length !== 0
    || vendorQualification.probes.deny.receipt_absent !== true) {
  throw new Error('vendor qualification: failed terminal and empty probe receipts required');
}
const failures = vendorTranscript.tool_results.filter((r: any) => r.is_error);
if (!failures.some((r: any) => r.content.includes('apply-seccomp') && r.content.includes('CAP_SYS_ADMIN'))
    || !failures.some((r: any) => r.content.includes('allowed_domains cannot widen network access'))) {
  throw new Error('vendor qualification: the policy rejection and the apply-seccomp crash must both appear');
}
if (vendorAudit.length < 1 || !vendorAudit.some((l: string) => l.includes('unpriv_bwrap') && l.includes('capname="sys_admin"'))) {
  throw new Error('vendor qualification: the kernel denial under unpriv_bwrap must be present');
}
if (vendorBatches.length !== 3 || vendorBatches.some((b: any) => b.status !== 'stopped' || b.attempts_claimed !== 1)) {
  throw new Error('vendor qualification: three launches, each stopped at its first slot');
}
if (vendorResults.counting.model_sessions !== 1 || vendorResults.counting.workflow_slots_run !== 0) {
  throw new Error('vendor qualification: exactly one model session and no workflow slots');
}
