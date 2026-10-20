// Tasks API for hosted apps: /api/service/tasks/*. Every route is pinned to the
// app its service token belongs to (requireTasksApp); a task id from another
// app answers 404, the same as one that does not exist.

import { Router } from 'express';
import { requireTasksApp } from '../services/tasksAppAuth.js';
import {
  createTask, listAppTasks, getAppTask, appComment, appSetStatus, appDelete, appEvents,
} from '../services/tasks.js';
import { getWebhook, setWebhook, validateWebhookUrl } from '../services/tasksWebhook.js';

const router = Router();
router.use(requireTasksApp);

router.post('/', (req, res) => {
  res.status(201).json({ task: createTask(req.tasksApp, req.body || {}) });
});

router.get('/', (req, res) => {
  res.json({ tasks: listAppTasks(req.tasksApp, req.query) });
});

router.get('/events', (req, res) => {
  res.json(appEvents(req.tasksApp, req.query.since, req.query.limit));
});

router.get('/webhook', (req, res) => {
  res.json({ webhook: getWebhook(req.tasksApp.id) });
});

router.put('/webhook', async (req, res) => {
  const raw = req.body?.url;
  const url = raw === null || raw === '' ? null : await validateWebhookUrl(raw);
  res.json({ webhook: setWebhook(req.tasksApp.id, url) });
});

router.get('/:id', (req, res) => {
  res.json({ task: getAppTask(req.tasksApp, req.params.id) });
});

router.post('/:id/comments', (req, res) => {
  res.status(201).json({ comment: appComment(req.tasksApp, req.params.id, req.body?.body) });
});

router.patch('/:id', (req, res) => {
  res.json({ task: appSetStatus(req.tasksApp, req.params.id, req.body?.status) });
});

router.delete('/:id', (req, res) => {
  appDelete(req.tasksApp, req.params.id);
  res.json({ deleted: true });
});

export default router;
