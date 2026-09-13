/**
 * AppStudio for a managed app whose repository lives on this AppCrane host
 * (apps.repo_backend = 'local').
 *
 * The owner's decision: analyze the local repo and turn the analysis into a
 * NEW request, instead of writing, building and pushing code. So for such an
 * app the pipeline is only `plan`, and its result is recorded differently:
 *
 *   originating request E            new request R
 *   ----------------------            -------------
 *   planning  (route queued `plan`)
 *     plan job runs against a clone of the branch tip
 *   done      (ai_log names R)  ───▶  new  (triage; message = the analysis,
 *                                            ai_log names E)
 *
 * Why these states:
 *   - E → 'done' is the status the reject and mark-done routes already use to
 *     close a request. It is terminal in the dashboard, drops E off the default
 *     request lists, and — unlike 'pending_user_review_plan' — offers no
 *     "approve plan" step that would queue a `code` job. E keeps no
 *     ai_plan_json for the same reason: approve-plan refuses a row without one.
 *   - R → 'new' is the triage bucket, which is what appcrane_list_requests
 *     bucket="triage" hands to whoever picks up work. R also carries no
 *     ai_plan_json, so it cannot be pushed into the code phase either; its
 *     analysis is in `message`, readable through every request surface.
 *   - R keeps E's requester (user_id / user_name), so the person who asked
 *     sees the follow-up in their own request list.
 *
 * Nothing is pushed, no branch is created and no deploy is started. The later
 * phases refuse a local app outright (refuseLocalRepoPhase) so a row that
 * reaches them anyway — an old plan approved, a retried job — fails with a
 * clear reason instead of trying GitHub.
 */

import { existsSync, mkdirSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../../db.js';
import { usesLocalRepo, localBranchHeadSha, cloneLocalRepoForDeploy } from '../managedRepo.js';

const MAX_MESSAGE_CHARS = 20000;

export { usesLocalRepo };

/** Throw for a phase AppStudio does not run for a local-repo app. */
export function refuseLocalRepoPhase(app, phase) {
  if (!usesLocalRepo(app)) return;
  throw new Error(
    `AppStudio does not run the '${phase}' phase for '${app.slug}': its repository is hosted on this AppCrane, ` +
    `so AppStudio analyzes it and files a new request instead of writing, building or pushing code.`,
  );
}

/**
 * Shallow clone of the app's branch tip for the planner to read.
 * Returns { dir, head } — `head` is the full commit the clone was taken at.
 */
export async function checkoutForAnalysis(app, jobId) {
  const branch = app.branch || 'main';
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const parent = join(dataDir, 'apps', app.slug, 'studio-analysis'); // nosemgrep: path-join-resolve-traversal — slug is DB-validated
  const dir = join(parent, String(jobId));
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(parent, { recursive: true });
  const head = await localBranchHeadSha(app, branch);
  await cloneLocalRepoForDeploy(app, dir, branch);
  return { dir, head, branch };
}

export function removeAnalysisCheckout(dir) {
  if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

const bullets = (items, fmt) => (Array.isArray(items) && items.length ? items.map((i) => `- ${fmt(i)}`).join('\n') : '');

export function analysisMessage({ enh, app, plan, summary, head, branch }) {
  const sections = [
    `AppStudio analysis of request #${enh.id} for ${app.slug} (AMC_${app.slug}, branch ${branch} @ ${head.slice(0, 8)}).`,
    `Original request:\n${enh.message}`,
    plan?.summary ? `Proposed change:\n${plan.summary}` : '',
    bullets(plan?.files_to_change, (f) => `${f.path} (${f.action})${f.rationale ? `: ${f.rationale}` : ''}`)
      ? `Files to change:\n${bullets(plan.files_to_change, (f) => `${f.path} (${f.action})${f.rationale ? `: ${f.rationale}` : ''}`)}` : '',
    bullets(plan?.test_files, (f) => `${f.path} (${f.action})${f.what ? `: ${f.what}` : ''}`)
      ? `Tests:\n${bullets(plan.test_files, (f) => `${f.path} (${f.action})${f.what ? `: ${f.what}` : ''}`)}` : '',
    bullets(plan?.risks, String) ? `Risks:\n${bullets(plan.risks, String)}` : '',
    bullets(plan?.open_questions, String) ? `Open questions:\n${bullets(plan.open_questions, String)}` : '',
    plan?.test_plan ? `Test plan:\n${plan.test_plan}` : '',
    !plan && summary ? `Analysis:\n${summary}` : '',
    'No code was written, built or pushed: this app\'s repository is hosted on this AppCrane. ' +
      'Implement it through appcrane_push_to_managed_app / appcrane_managed_patch.',
  ].filter(Boolean);
  const text = sections.join('\n\n');
  return text.length > MAX_MESSAGE_CHARS ? `${text.slice(0, MAX_MESSAGE_CHARS)}\n…(truncated)` : text;
}

/**
 * Close E and file R in one transaction. Returns R's id.
 * Throws — failing the job — when the planner produced nothing to file.
 */
export function recordAnalysisAsRequest({ job, enh, app, result, head, branch }) {
  if (!result.plan && !String(result.summary || '').trim()) {
    throw new Error('The analysis produced no plan and no summary; no request was created.');
  }
  const db = getDb();
  const costCents = Math.ceil(result.costUsd * 100);
  const tokens = result.tokensIn + result.tokensOut;
  const now = new Date().toISOString();
  const message = analysisMessage({ enh, app, plan: result.plan, summary: result.summary, head, branch });

  return db.transaction(() => {
    const newId = db.prepare(`
      INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, ai_log)
      VALUES (?, ?, ?, ?, 'new', ?)
    `).run(
      enh.app_slug, enh.user_id, enh.user_name, message,
      `\n[${now}] Filed by AppStudio from the analysis of request #${enh.id} (${branch} @ ${head.slice(0, 8)}).\n`,
    ).lastInsertRowid;

    db.prepare(`
      UPDATE enhancement_requests
      SET status = 'done',
          ai_cost_estimate = ?,
          cost_tokens = cost_tokens + ?,
          cost_usd_cents = cost_usd_cents + ?,
          ai_log = COALESCE(ai_log, '') || ?
      WHERE id = ?
    `).run(
      JSON.stringify({ tokensIn: result.tokensIn, tokensOut: result.tokensOut, costUsd: result.costUsd }),
      tokens,
      costCents,
      `\n[${now}] Analyzed ${branch} @ ${head.slice(0, 8)} ($${result.costUsd.toFixed(4)}, ${tokens} tokens). ` +
        `This app's repository is hosted on this AppCrane, so AppStudio does not write, build or push code; ` +
        `the analysis was filed as request #${newId}.\n`,
      enh.id,
    );
    db.prepare('UPDATE enhancement_jobs SET output_json = ?, cost_tokens = ?, cost_usd_cents = ? WHERE id = ?')
      .run(JSON.stringify({ plan: result.plan, filed_request_id: newId }), tokens, costCents, job.id);
    return newId;
  })();
}
