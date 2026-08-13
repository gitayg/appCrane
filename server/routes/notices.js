import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { globalNotices, noticesForApp } from '../services/platformNotices.js';

const router = Router();

/**
 * GET /api/notices — platform notices that apply to every app.
 *
 * ANONYMOUS ON PURPOSE, and the same trust class as /api/info, which already
 * serves the version, the init state and the Caddy reload outcome without
 * credentials. A global notice is platform-authored prose about a platform
 * release: it names no app, no slug, no user and no configuration. What it
 * costs to disclose is roughly "this box runs AppCrane and AppCrane 2.39.0
 * changed how identity reaches apps" — which the version field on /api/info
 * already tells you.
 *
 * What being public buys is the whole point of the channel. The person who
 * needs this most is an app author whose container just started 401-ing, from
 * inside that container, with no platform credentials to hand; requiring auth
 * would reproduce the silence this exists to fix. Notices are also worth reading
 * BEFORE you have an account on the box you are deploying to.
 *
 * The app-scoped route below is deliberately NOT public: see its comment.
 */
router.get('/notices', (req, res) => {
  res.json({ notices: globalNotices() });
});

/**
 * GET /api/apps/:slug/notices — global notices plus those scoped to this app.
 *
 * AUTHENTICATED AND PER-APP AUTHORIZED, unlike the route above. Two different
 * things leak here and both matter. A scoped notice states a fact about the
 * app's configuration ("your app is in headless mode, so it receives no
 * identity headers") — that is an operational detail about someone else's
 * deployment, not a platform release note. And answering at all distinguishes a
 * real slug from a 404, which enumerates the fleet.
 *
 * requireAppAccess (not merely requireAuth) because this is an app-scoped
 * resource: any authenticated user could otherwise read the configuration
 * posture of every app on the box, one slug at a time.
 */
router.get('/apps/:slug/notices', requireAuth, requireAppAccess, (req, res) => {
  res.json({ slug: req.app.slug, notices: noticesForApp(req.app) });
});

export default router;
