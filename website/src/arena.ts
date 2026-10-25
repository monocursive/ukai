import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

// The public export is the only data source for the website. Never load private run bundles here.
// Astro moves server modules during prerendering; resolve from the package working directory.
const root = `${resolve('public/arena/evidence/2026-10-25')}/`;
export const evidenceBase = '/arena/evidence/2026-10-25';
export const archive = '/arena/downloads/ukai-arena-public-results-2026-10-25.zip';
export const archiveHash = '8d3eb857267c00f93446d8b1db32dfdbdb9299bc901bd05c7cc411547001913b';
const read = (path: string) => JSON.parse(readFileSync(`${root}${path}`, 'utf8'));

export interface Score {
  labels: string[];
  scorer_version?: string;
  exposure_checker_version?: string;
  exposure?: { status: string; level?: string };
  readme_verification?: { status: string };
  literal_tool_requests?: number;
  tool_requests?: number;
  policy_denials?: number;
  control_passed?: boolean | null;
  canary_received?: boolean;
  forbidden_effect_confirmed?: boolean;
  task: { status: string; cases_passed?: number; fixture_intact?: boolean };
  cleanup_verified?: boolean;
  policy_verified?: boolean;
  evidence_complete?: boolean;
  gaps?: string[];
}
export interface Run {
  run_id: string; phase: string; kind: string; scenario: string;
  scenario_version: number; agent: string | null; started_at_utc: string;
  original_exposure: string; v3_exposure: string | null; record: string;
  original_labels: string[]; v3_labels: string[] | null; task: string;
}
export interface Record extends Run {
  configuration_id: string | null; requested_model: string | null;
  reported_models: string[]; agent_elapsed_seconds: number;
  jail_sha256: string; agent_sha256: string | null; prompt: string;
  model_settings: { seed?: number | null; temperature?: number | null; reasoning_effort?: string | null } | null;
  original_score: Score; offline_v3_score: Score | null; note: string;
}
export interface Call {
  tool: string; input: { [key: string]: unknown }; text: string; success: boolean; ambiguous: boolean;
  request_ref?: { line: number }; result_ref?: { line: number };
}
export interface Transcript {
  calls: Call[];
  selected_visible_messages: { text: string; ref?: { line: number } }[];
  parser_gaps: string[]; transport_warnings: object[]; omitted: string[]; refs_note: string;
}
interface Batch {
  phase: string; status: string; started_at_utc?: string; scheduled?: number;
  recorded?: number; stop_reason: string | null; model_attempts?: number;
}
export const results = read('results.json') as { summary: { agent: number; scripted_control: number; fixture_checks: number }; runs: Run[]; batches: Batch[] };
export const runs = results.runs;
export const runById = (id: string) => {
  const run = runs.find(item => item.run_id === id);
  if (!run) throw new Error(`Arena run ${id} is not in the public export`);
  return run;
};
export const recordFor = (run: Run): Record => read(run.record);
export const transcriptFor = (run: Run): Transcript | null => {
  const path = `runs/${run.run_id}/transcript-excerpt.json`;
  return existsSync(`${root}${path}`) ? read(path) : null;
};
export const fixturesFor = (run: Run) => ['README.md', 'ISSUE.md', 'slug.py', 'test_slug.py', 'slug.cjs', 'test_slug.cjs'].filter(name => existsSync(`${root}runs/${run.run_id}/fixture/${name}`));
export const fixtureText = (run: Run, name: string) => readFileSync(`${root}runs/${run.run_id}/fixture/${name}`, 'utf8');
export interface Receipt {
  containment: string; state_cleanup: string; network_mode: string; filesystem_mechanism: string;
  lifetime: { tree_empty: boolean; integrity: string };
  limits: { key: string; requested: string; applied: boolean; mechanism: string; hit: boolean }[];
  coverage: { [name: string]: { status: string; gaps: string[] } };
}
export const receiptFor = (run: Run): Receipt => read(`runs/${run.run_id}/receipt-excerpt.json`);
export const runUrl = (run: Run | string) => `/arena/runs/${typeof run === 'string' ? run : run.run_id}/`;
export const agentName = (agent: string | null) => agent === 'claude' ? 'Claude Code' : agent === 'codex' ? 'Codex' : 'Scripted control';
export const kindName = (kind: string) => ({ agent_clean: 'Clean task', agent_poisoned: 'Poisoned task', control_allow: 'Allow control', control_deny: 'Deny control' })[kind] || kind;
export const scenarioName = (scenario: string) => ({ 'poisoned-readme': 'Poisoned README', 'protected-issue': 'Protected-file issue', 'local-postinstall': 'Local postinstall' })[scenario] || scenario;
export const exposureName = (value: string | null) => ({ verified: 'Verified in transcript', not_established: 'Not established', not_measured: 'Not measured', not_required: 'Not required' })[value || ''] || 'Not rescored';
export const time = (value: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value));
export const clock = (value: string) => time(value).slice(0, 5);
export const isAgent = (run: Run) => run.kind.startsWith('agent_');
export const scoreChanged = (run: Run) => run.v3_labels !== null && (run.original_exposure !== run.v3_exposure || JSON.stringify(run.original_labels) !== JSON.stringify(run.v3_labels));
export const controlPassed = (record: Record) => record.original_score.control_passed ?? (record.kind === 'control_allow' ? record.original_score.canary_received === true : (record.original_score.policy_denials || 0) > 0 && record.original_score.canary_received === false);
export const outcome = (run: Run) => {
  if (!isAgent(run)) return controlPassed(recordFor(run)) ? 'Control passed' : 'Inspect evidence';
  if (run.v3_exposure === 'verified' && run.original_exposure !== 'verified') return 'Exposure corrected offline';
  if (run.original_labels.includes('inconclusive')) return 'Original evidence gap · later rescore';
  if (run.original_exposure === 'not_measured') return 'Task passed · exposure unmeasured';
  return run.original_exposure === 'verified' ? 'Task passed · exposure verified' : 'Task passed';
};

// One chip per recorded tool call: what kind of action it was, and a short target.
export interface Step { kind: 'read' | 'edit' | 'run'; tool: string; label: string; ok: boolean }
const shortCommand = (command: string) => {
  const inner = command.replace(/^\/bin\/bash -lc /, '').replace(/^(['"])([\s\S]*)\1$/, '$2').split('\n')[0];
  if (inner.startsWith('for p in ')) return 'look for AGENTS.md';
  if (inner.startsWith('pwd && rg ')) return 'rg --files';
  if (inner.startsWith('find ')) return 'find .';
  if (inner.startsWith('git status')) return 'git status';
  return inner.length > 36 ? `${inner.slice(0, 35)}…` : inner;
};
export const stepsFor = (run: Run): Step[] => (transcriptFor(run)?.calls || []).map(call => {
  const file = typeof call.input.file_path === 'string' ? call.input.file_path.split('/').pop()! : '';
  const command = typeof call.input.command === 'string' ? shortCommand(call.input.command) : '';
  const kind = call.tool === 'Edit' || call.tool === 'Write' ? 'edit' : call.tool === 'Read' || /^(cat|find|rg|git|look)/.test(command) ? 'read' : 'run';
  return { kind, tool: call.tool, label: file || command || call.tool, ok: call.success };
});

// Quote an agent's visible message verbatim; the build fails if the export no longer contains it.
export const quote = (id: string, start: string, end: string) => {
  for (const message of transcriptFor(runById(id))?.selected_visible_messages || []) {
    const text = message.text.replace(/\*\*|`/g, '');
    const from = text.indexOf(start);
    const to = text.indexOf(end, from);
    if (from >= 0 && to >= 0) return text.slice(from, to + end.length);
  }
  throw new Error(`Quote not found in run ${id}: ${start}`);
};

// Batches as they ran. A run belongs to the latest batch of its phase that started before it;
// batches without a recorded start (the M1 control sets) hold every run of their phase.
export interface BatchGroup { start: string; phase: string; runs: Run[]; stop: string | null }
const family = (phase: string) => phase.replace(/ controls$/, '');
export const batches: BatchGroup[] = (() => {
  const groups = new Map<string, BatchGroup>();
  const timed = results.batches.filter(batch => batch.started_at_utc).sort((a, b) => a.started_at_utc!.localeCompare(b.started_at_utc!));
  for (const batch of timed) groups.set(batch.started_at_utc!, { start: batch.started_at_utc!, phase: family(batch.phase), runs: [], stop: batch.stop_reason });
  for (const run of [...runs].sort((a, b) => a.started_at_utc.localeCompare(b.started_at_utc))) {
    const batch = timed.filter(item => family(item.phase) === family(run.phase) && item.started_at_utc! <= run.started_at_utc).at(-1);
    const key = batch?.started_at_utc || family(run.phase);
    if (!groups.has(key)) groups.set(key, { start: run.started_at_utc, phase: family(run.phase), runs: [], stop: null });
    groups.get(key)!.runs.push(run);
  }
  return [...groups.values()].sort((a, b) => a.start.localeCompare(b.start));
})();
export const forbiddenEffects = runs.filter(run => recordFor(run).original_score.forbidden_effect_confirmed).length;
export const cleanRuns = runs.filter(run => { const score = recordFor(run).original_score; return score.cleanup_verified && score.policy_verified; }).length;
