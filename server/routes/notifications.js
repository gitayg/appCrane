import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/apps/:slug/notifications - Get notification config
 */
router.get('/:slug/notifications', requireAppAccess, (req, res) => {
  const db = getDb();
  const config = db.prepare(
    'SELECT * FROM notification_configs WHERE user_id = ? AND app_id = ?'
  ).get(req.user.id, req.app.id);

  res.json({ config: config || null });
});

/**
 * PUT /api/apps/:slug/notifications - Update notification config
 */
router.put('/:slug/notifications', requireAppUser, (req, res) => {
  const { email, on_deploy_success, on_deploy_fail, on_app_down, on_app_recovered } = req.body;
  const db = getDb();

  if (!email) throw new AppError('Email is required', 400, 'VALIDATION');

  db.prepare(`
    INSERT INTO notification_configs (user_id, app_id, email, on_deploy_success, on_deploy_fail, on_app_down, on_app_recovered)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, app_id) DO UPDATE SET
      email = excluded.email,
      on_deploy_success = excluded.on_deploy_success,
      on_deploy_fail = excluded.on_deploy_fail,
      on_app_down = excluded.on_app_down,
      on_app_recovered = excluded.on_app_recovered
  `).run(
    req.user.id, req.app.id, email,
    on_deploy_success ? 1 : 0,
    on_deploy_fail ? 1 : 0,
    on_app_down ? 1 : 0,
    on_app_recovered ? 1 : 0,
  );

  const config = db.prepare(
    'SELECT * FROM notification_configs WHERE user_id = ? AND app_id = ?'
  ).get(req.user.id, req.app.id);

  res.json({ config, message: 'Notification preferences updated' });
});

/**
 * POST /api/apps/:slug/notifications/test - Send test notification email
 */
router.post('/:slug/notifications/test', requireAppUser, async (req, res) => {
  const db = getDb();
  const config = db.prepare(
    'SELECT * FROM notification_configs WHERE user_id = ? AND app_id = ?'
  ).get(req.user.id, req.app.id);

  if (!config) throw new AppError('Configure notifications first', 400, 'NOT_CONFIGURED');

  try {
    const { sendEmail } = await import('../services/emailService.js');
    await sendEmail({
      to: config.email,
      subject: `[DeployHub] Test notification for ${req.app.name}`,
      text: `This is a test notification from DeployHub for app "${req.app.name}" (${req.app.slug}).\n\nIf you received this, notifications are working correctly.`,
    });
    res.json({ message: `Test email sent to ${config.email}` });
  } catch (e) {
    res.json({ message: `Email sending failed: ${e.message}. Check SMTP settings.`, error: true });
  }
});

export default router;
