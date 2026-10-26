import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

// The 26 October boundary-evaluation export is the only data source for the boundary views.
// Never load private run bundles here; the 25 October package stays in ./arena.ts untouched.
const root = `${resolve('public/arena/evidence/2026-10-26-workflow-v2')}/`;
export const boundaryEvidenceBase = '/arena/evidence/2026-10-26-workflow-v2';
export const boundaryArchive = '/arena/downloads/ukai-arena-containment-2026-10-26-v2.zip';
export const boundaryArchiveHash = readFileSync(resolve(`public${boundaryArchive}.sha256`), 'utf8').split(' ')[0];
export const boundaryArchiveKB = Math.ceil(statSync(resolve(`public${boundaryArchive}`)).size / 1024);
const read = (path: string) => JSON.parse(readFileSync(`${root}${path}`, 'utf8'));

export interface BoundaryRun {
  run_id: string; group: 'scripted_control' | 'agent_boundary_probe' | 'agent_workflow'; phase: string; kind: string;
  agent: string | null; label: string | null; control_passed: boolean | null; started_at_utc: string;
  record: string; suite_label?: string; control_label?: string; family?: string; variant?: string;
}
export interface Layer { status: string; reason?: string | null; refs?: unknown[]; note?: string; evidence?: string[] }
export interface BoundaryRecord extends BoundaryRun {
  labels: string[]; terminal?: string | null; gaps: string[]; protocol_deviations: string[];
  policy_denials: number; collector_requests: number; canary_received: boolean;
  forbidden_effect_confirmed?: boolean; violation_confirmed?: boolean;
  cleanup_verified: boolean; policy_verified: boolean; evidence_complete: boolean;
  attribution: string; tool_to_proxy_process_link_verified: boolean;
  literal_upload_requests?: number; requested_model?: string | null; agent_configuration_id?: string | null;
  reported_models?: string[]; scorer_version: string; exit_code?: number | null; wall_limit_hit?: boolean;
  policy_read_denials: null; operation?: Layer & { level?: string; install_calls?: number };
  policy?: Layer & { target?: string | null; grant_kind?: string }; enforcement?: Layer; effect?: Layer;
  utility?: Layer; expected?: string; lifecycle?: { started_at?: string; ended_at?: string; settled?: boolean; terminal_result?: string; stop_reason?: string | null };
  original_class: string; slot?: string; ended_at_utc?: string; jail_sha256?: string; agent_sha256?: string | null;
  prompt?: string | null; frozen_command: string[]; fixture?: { [name: string]: string }; limits_profile?: string;
  post_state?: { [key: string]: boolean | string | null };
  hook_execution_verified?: null; proxy_actor?: string;
  task?: { status: string; cases_passed: number };
  question: string; tested_conditions: string; claim_supported: string; limitation: string;
}
export interface BoundaryTranscript {
  calls: { tool: string; input: { [key: string]: unknown }; text: string; success: boolean; ambiguous: boolean; request_ref?: { line: number }; result_ref?: { line: number } }[];
  selected_visible_messages: { text: string; ref?: { line: number } }[]; parser_gaps: string[]; refs_note: string;
}
export interface TraceExcerpt { proxy_results_for_collector: { line: number; decision: string; destination: string; reason: string | null; request_id: number | string; observed_at: string }[]; note: string }
export interface CollectorExcerpt { rows: { line: number; canary_match?: boolean; body_sha256?: string; body_bytes?: number; received_at?: string; malformed?: boolean }[]; note: string }
export interface BoundaryReceipt {
  containment: string; state_cleanup: string; network_mode: string; filesystem_mechanism: string;
  lifetime: { tree_empty: boolean; integrity: string };
  limits: { key: string; requested: string; applied: boolean; mechanism: string; hit: boolean }[];
  coverage: { [name: string]: { status: string; gaps: string[] } };
}

export const boundaryResults = read('results.json') as {
  summary: { scripted_controls: number; agent_boundary_probes: number; agent_workflow_attempts: number; note: string };
  batches: { phase: string; status: string; scheduled?: number; recorded?: number; model_attempts?: number; cases?: number; passed?: number; exported?: boolean; reason?: string }[];
  runs: BoundaryRun[]; publication_status: string;
};
export const boundaryRuns = boundaryResults.runs;
export const boundaryById = (id: string) => {
  const run = boundaryRuns.find(item => item.run_id === id);
  if (!run) throw new Error(`Boundary run ${id} is not in the public export`);
  return run;
};
export const boundaryRecord = (run: BoundaryRun): BoundaryRecord => read(run.record);
export const boundaryTranscript = (run: BoundaryRun): BoundaryTranscript | null => {
  const path = `runs/${run.run_id}/transcript-excerpt.json`;
  return existsSync(`${root}${path}`) ? read(path) : null;
};
export const boundaryTrace = (run: BoundaryRun): TraceExcerpt => read(`runs/${run.run_id}/trace-excerpt.json`);
export const boundaryCollector = (run: BoundaryRun): CollectorExcerpt => read(`runs/${run.run_id}/collector-excerpt.json`);
export const boundaryReceipt = (run: BoundaryRun): BoundaryReceipt => read(`runs/${run.run_id}/receipt-excerpt.json`);
export const boundaryUrl = (run: BoundaryRun | string) => `/arena/boundary/${typeof run === 'string' ? run : run.run_id}/`;
export const isProbe = (run: BoundaryRun) => run.group === 'agent_boundary_probe';
export const probes = boundaryRuns.filter(isProbe);
export const suiteCases = boundaryRuns.filter(run => run.suite_label);
export const pilotControls = boundaryRuns.filter(run => run.group === 'scripted_control' && run.phase === '26 October boundary pilot');
export const workflows = boundaryRuns.filter(run => run.group === 'agent_workflow');
export const workflowControls = boundaryRuns.filter(run => run.phase === '26 October workflow controls');
export const familyName = (family?: string) => ({ net: 'Network', child: 'Child process', read: 'Protected read', write: 'Protected write', time: 'Wall deadline', dependency: 'Dependency hook' })[family || ''] || 'Upload';
export const outcomeName = (label: string | null) => ({
  allow_delivered: 'Granted · delivered', request_observed_with_denial: 'Request seen · denied',
  allow_read_succeeded: 'Granted · read', specified_read_failed: 'Ungranted · read failed',
  allow_write_applied: 'Granted · written', specified_write_prevented: 'Read-only · unchanged',
  completed_before_deadline: 'Finished in time', deadline_enforced_and_tree_settled: 'Deadline hit · tree gone',
  clean_install_no_collector_traffic: 'Clean install · silent',
  clean_workflow_completed_without_collector_traffic: 'Task passed · no traffic',
  workflow_completed_with_containment: 'Task passed · request denied',
})[label || ''] || label || 'Inspect evidence';
export const agentLabel = (agent: string | null) => agent === 'claude' ? 'Claude Code' : agent === 'codex' ? 'Codex' : 'Scripted control';

// Build-time guard: the page's statements must match the export.
export const boundaryMust = (ok: boolean, what: string) => { if (!ok) throw new Error(`Boundary page claim no longer matches the export: ${what}`); };
