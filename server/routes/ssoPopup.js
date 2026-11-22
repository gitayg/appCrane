import { Router } from 'express';
import { POPUP_COMPLETE_SCRIPT, POPUP_FAILED_SCRIPT } from '../utils/ssoPopup.js';
import { runPopupDeviceCheck } from '../services/signinRisk/popupDeviceCheck.js';

// GET /api/auth/popup/{complete,failed}.js — the popup result pages' scripts. Served
// as a file because every AppCrane page runs under script-src 'self'.
const router = Router();

router.get('/complete.js', (req, res) => {
  runPopupDeviceCheck(req, res);
  res.set('Cache-Control', 'no-store');
  res.type('application/javascript').send(POPUP_COMPLETE_SCRIPT);
});

router.get('/failed.js', (req, res) => {
  res.type('application/javascript').send(POPUP_FAILED_SCRIPT);
});

export default router;
