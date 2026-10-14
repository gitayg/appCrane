// fetch() for AppCrane's own probes of an app's port on this host (health
// checks, live-version, the post-deploy probe).
//
// The URL is always http://localhost:<the app's port><path>, but the RESPONSE
// comes from app code, which is untrusted. fetch() follows redirects by
// default, so an app answering its health path with
// `302 Location: http://169.254.169.254/...` or `http://127.0.0.1:2019/config/`
// had AppCrane request that address — and the health-test route, the MCP
// health tool and the deploy log hand the body back to the caller.
//
// Redirects are still followed while they stay on the same origin (an app
// that 301s /health to /health/ keeps working); a redirect anywhere else is
// returned as the 3xx it is, and the probe reads it as unhealthy.

const MAX_REDIRECTS = 5;

export async function fetchAppProbe(url, options = {}) {
  let current = new URL(url);
  for (let hop = 0; ; hop++) {
    const res = await fetch(current, { ...options, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location || hop >= MAX_REDIRECTS) return res;
    let next;
    try { next = new URL(location, current); } catch { return res; }
    if (next.origin !== current.origin) return res;
    await res.body?.cancel().catch(() => {});
    current = next;
  }
}
