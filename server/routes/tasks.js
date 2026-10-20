// "My tasks": one inbox per person across every app. Only the requester and
// the assignee of a task (while they still have access to its app) see it;
// role rules live in services/tasks.js.

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  listMyTasks, myTaskCounts, getMyTask, userComment, userSetStatus, userDelete,
} from '../services/tasks.js';

const router = Router();
router.use(requireAuth);

router.get('/', (req, res) => {
  res.json({ tasks: listMyTasks(req.user, req.query) });
});

router.get('/count', (req, res) => {
  res.json(myTaskCounts(req.user));
});

router.get('/:id', (req, res) => {
  res.json({ task: getMyTask(req.user, req.params.id) });
});

router.post('/:id/comments', (req, res) => {
  res.status(201).json({ comment: userComment(req.user, req.params.id, req.body?.body) });
});

router.patch('/:id', (req, res) => {
  res.json({ task: userSetStatus(req.user, req.params.id, req.body?.status) });
});

router.delete('/:id', (req, res) => {
  userDelete(req.user, req.params.id);
  res.json({ deleted: true });
});

export default router;
