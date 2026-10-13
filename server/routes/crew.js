import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  roster, crewLog, registerAgent, removeAgent, decideConnection,
  blockAgent, listBlocks, unblock, assertCrewCaller,
} from '../services/crew.js';
import { issueInitialToken, rotateAgentToken, revokeAgentToken, tokenStatusFor } from '../services/crewTokens.js';
import { crewMap } from '../services/crewMap.js';
import { decideTask, waitingForMe, myRules, addRule, editRule, removeRule } from '../services/crewDecisions.js';

/**
 * Crew for the dashboard (v2.105.0). Rules live in services/crew.js; this file
 * only maps HTTP onto them. Every write here is a PERSON's decision, so audit
 * rows are tagged 'human' (agents use the MCP tools, tagged 'agent').
 *
 * Ownership is checked per row inside the service, never by trusting the URL:
 *   - DELETE /agents/:name        → agentForCaller (the caller owns the agent)
 *   - POST /connections/:id/...   → connection.to_owner_id === caller
 *   - DELETE /blocks/:id          → block.owner_user_id === caller
 * A platform admin passes none of these for someone else's rows: an admin sees
 * the whole roster (with block counts) but decides only for themself.
 *
 * Registering a hosted agent takes a PASTED card or form fields. There is no
 * "card URL" fetch in phase 1: that would let any logged-in user make the
 * server request an address of their choosing (SSRF).
 *
 * Phase 2: registering a NEW hosted agent returns its A2A token once
 * (`a2a_token`); POST/DELETE /agents/:name/token rotate or revoke it, both
 * through agentForCaller (the caller owns the agent). GET /map returns the
 * communication map: counts only, see services/crewMap.js.
 *
 * Phase 3 (people in the loop), same per-row ownership inside the service:
 *   - POST /decisions/:id          → decision.decider_user_id === caller
 *                                    (the one person the question was routed to)
 *   - GET/POST/PATCH/DELETE /rules → rule.owner_user_id === caller; a person
 *                                    lists and changes only their own rules
 *   - GET /waiting                 → the caller's own pending questions and
 *                                    first contacts (the Crew nav badge)
 */
const router = Router();
router.use(requireAuth);
// Security fix after v2.105.0: an agent identity cannot own crew agents on
// any channel, the dashboard included (services/crew.js assertCrewCaller).
router.use((req, _res, next) => {
  try { assertCrewCaller(req.user, 'dashboard'); next(); } catch (e) { next(e); }
});

router.get('/roster', (req, res) => {
  res.json({ agents: roster(req.user, { skill: req.query.skill }) });
});

router.get('/log', (req, res) => {
  res.json({ entries: crewLog(req.user, { limit: req.query.limit }) });
});

router.get('/agents', (req, res) => {
  res.json({ agents: roster(req.user).filter((a) => a.is_mine), tokens: tokenStatusFor(req.user) });
});

router.get('/map', (req, res) => {
  res.json(crewMap(req.user));
});

router.post('/agents/:name/token', (req, res) => {
  res.status(201).json(rotateAgentToken(req.user, req.params.name));
});

router.delete('/agents/:name/token', (req, res) => {
  res.json(revokeAgentToken(req.user, req.params.name));
});

router.post('/agents', (req, res) => {
  const b = req.body || {};
  const agent = registerAgent(req.user, {
    name: b.name, description: b.description, skills: b.skills,
    knows_about: b.knows_about, card_json: b.card_json,
  }, { kind: 'hosted', actorKind: 'human' });
  // A new hosted agent gets its A2A token now, shown once. Re-registering an
  // existing name never issues one: rotation is an explicit act.
  const a2a = agent.created ? issueInitialToken(req.user, agent.name) : null;
  res.status(agent.created ? 201 : 200).json({ agent, ...(a2a ? { a2a_token: a2a.token, a2a_token_note: a2a.note } : {}) });
});

router.delete('/agents/:name', (req, res) => {
  res.json(removeAgent(req.user, req.params.name, { actorKind: 'human' }));
});

router.post('/connections/:id/decision', (req, res) => {
  const b = req.body || {};
  res.json(decideConnection(req.user, req.params.id, b.decision, { task_id: b.task_id }));
});

router.get('/waiting', (req, res) => {
  res.json(waitingForMe(req.user));
});

router.post('/decisions/:id', (req, res) => {
  const b = req.body || {};
  res.json(decideTask(req.user, req.params.id, { decision: b.decision, message: b.message, expires_in_days: b.expires_in_days }));
});

router.get('/rules', (req, res) => {
  res.json(myRules(req.user));
});

router.post('/rules', (req, res) => {
  const b = req.body || {};
  const r = addRule(req.user, { agent: b.agent, action: b.action, scope: b.scope, expires_in_days: b.expires_in_days });
  res.status(r.created ? 201 : 200).json(r);
});

router.patch('/rules/:id', (req, res) => {
  res.json(editRule(req.user, req.params.id, { expires_in_days: (req.body || {}).expires_in_days }));
});

router.delete('/rules/:id', (req, res) => {
  res.json(removeRule(req.user, req.params.id));
});

router.get('/blocks', (req, res) => {
  res.json(listBlocks(req.user));
});

router.post('/blocks', (req, res) => {
  res.status(201).json(blockAgent(req.user, (req.body || {}).agent));
});

router.delete('/blocks/:id', (req, res) => {
  res.json(unblock(req.user, req.params.id));
});

export default router;
