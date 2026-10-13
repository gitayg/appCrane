import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  roster, crewLog, registerAgent, removeAgent, decideConnection,
  blockAgent, listBlocks, unblock,
} from '../services/crew.js';

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
 */
const router = Router();
router.use(requireAuth);

router.get('/roster', (req, res) => {
  res.json({ agents: roster(req.user, { skill: req.query.skill }) });
});

router.get('/log', (req, res) => {
  res.json({ entries: crewLog(req.user, { limit: req.query.limit }) });
});

router.get('/agents', (req, res) => {
  res.json({ agents: roster(req.user).filter((a) => a.is_mine) });
});

router.post('/agents', (req, res) => {
  const b = req.body || {};
  const agent = registerAgent(req.user, {
    name: b.name, description: b.description, skills: b.skills,
    knows_about: b.knows_about, card_json: b.card_json,
  }, { kind: 'hosted', actorKind: 'human' });
  res.status(agent.created ? 201 : 200).json({ agent });
});

router.delete('/agents/:name', (req, res) => {
  res.json(removeAgent(req.user, req.params.name, { actorKind: 'human' }));
});

router.post('/connections/:id/decision', (req, res) => {
  const b = req.body || {};
  res.json(decideConnection(req.user, req.params.id, b.decision, { task_id: b.task_id }));
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
