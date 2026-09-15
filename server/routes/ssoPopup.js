import { Router } from 'express';
import { POPUP_COMPLETE_SCRIPT } from '../utils/ssoPopup.js';

// GET /api/auth/popup/complete.js — the popup completion page's script. Served
// as a file because every AppCrane page runs under script-src 'self'.
const router = Router();

router.get('/complete.js', (req, res) => {
  res.type('application/javascript').send(POPUP_COMPLETE_SCRIPT);
});

export default router;
