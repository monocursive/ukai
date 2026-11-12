import fs from 'node:fs';
import path from 'node:path';
import { retryRuns, retryPair, retryRunLink } from './arena_replay_retry';
import { correction, sessions } from './arena_release_report';
import { novemberRuns } from './arena_november';

// The home page's Arena section. Every figure it prints is read from the
// evidence at build time; the build stops if a statement no longer holds.
const fail = (message: string) => { throw new Error(`arena home: ${message}`); };

// The measured incident-replay pair (field note 004). arena_replay_retry has
// already checked the three slots; these are the extra facts this section states.
const [, contained, bare] = retryRuns;
const shared = retryPair.shared;
if (retryPair.left.run_id !== bare.run_id || retryPair.right.run_id !== contained.run_id) fail('pair lanes changed');
if (!shared.task_prompt_sha256 || shared.structural_difference.no_other_meaningful_difference !== true) {
  fail('the pair no longer proves one prompt and structurally identical fixtures');
}
const routes = retryPair.left.refs.map((r: any) => r.route).join();
if (routes !== 'hook,nested') fail('the bare lane no longer has one delivery per route');
for (const run of [contained, bare]) {
  if (run.task.status !== 'pass' || run.task.trusted_check_verified !== true) fail(`${run.run_id}: trusted task check changed`);
}
if (contained.effect.received_at.length !== 0) fail('the contained lane has a delivery');

const clock = (stamp: string) => `${stamp.slice(11, 19)} UTC`;
const day = new Date(retryPair.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
export const pair = {
  measured: day,
  bare: {
    link: retryRunLink(bare),
    checks: bare.task.cases_passed,
    hookAt: clock(retryPair.left.refs[0].received_at),
    hookStamp: retryPair.left.refs[0].received_at,
    nestedAt: clock(retryPair.left.refs[1].received_at),
    nestedStamp: retryPair.left.refs[1].received_at,
    copies: bare.effect.received_at.length,
  },
  contained: {
    link: retryRunLink(contained),
    checks: contained.task.cases_passed,
    hostDenials: contained.policy_denials,
    keyRefusals: contained.credential_denials,
    copies: contained.effect.received_at.length,
  },
};

// The inventory, from the evaluation index next to the website in the repository.
const indexPath = path.join(process.cwd(), '..', 'arena', 'evaluation-index.json');
if (!fs.existsSync(indexPath)) fail('arena/evaluation-index.json is required to build the home page');
const runs = JSON.parse(fs.readFileSync(indexPath, 'utf8')).runs;
const ids = new Set(runs.map((r: any) => r.run_id));
if (ids.size !== runs.length) fail('the index repeats a run');
// Counted the way arena/evaluation_index.py counts: a run with an agent cohort is a
// session, every other run is a scripted control.
const agentRuns = runs.filter((r: any) => Boolean(r.cohort?.agent));
export const inventory = {
  sessions: agentRuns.length,
  controls: runs.length - agentRuns.length,
  corrected: runs.filter((r: any) => (r.corrections || []).length > 0).length,
};
if (runs.some((r: any) => !r.cohort?.agent && r.cohort?.scripted !== true)) fail('a run is neither an agent session nor a scripted control');

// The corrected study (field note 006).
export const corrected = { sessions: sessions.length, defects: correction.harness_defects.length };
if (corrected.sessions !== 6 || corrected.defects !== 5) fail('the corrected study states six sessions and five defects');

// The reader lab download named in the section.
export const labArchive = '/arena/downloads/ukai-arena-reader-lab-2026-11-01.zip';
if (!fs.existsSync(path.join(process.cwd(), 'public', labArchive))) fail('reader lab archive missing');
const lab = novemberRuns.filter((r: any) => r.phase === 'reader-lab' && r.group === 'scripted_control');
if (lab.length === 0 || !lab.every((r: any) => r.control_passed === true)) fail('reader lab controls changed');
export const labControls = lab.length;
