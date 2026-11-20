// Per-IP cap on NEW SSO sign-up requests (services/ssoSignupRequests.js). A
// public provider lets anyone with an account there file one, so one client
// could otherwise fill the queue. The IP is req.ip, which the trust-proxy
// setting (utils/clientIp.js) decides. In memory, per process: a restart
// forgets the counts, which only ever lets more through.

export const SIGNUP_PER_IP = 5;
export const SIGNUP_WINDOW_MS = 60 * 60 * 1000;
const MAX_IPS = 10_000;
const hits = new Map(); // ip -> timestamps, oldest first; Map order = least recently used

function recent(ip, nowMs) {
  const list = (hits.get(ip) || []).filter((t) => nowMs - t < SIGNUP_WINDOW_MS);
  if (list.length) hits.set(ip, list); else hits.delete(ip);
  return list;
}

/** True when this IP already filed SIGNUP_PER_IP new requests within the window. */
export function signupLimited(ip, nowMs = Date.now()) {
  return recent(ip || 'unknown', nowMs).length >= SIGNUP_PER_IP;
}

export function noteSignup(ip, nowMs = Date.now()) {
  const key = ip || 'unknown';
  const list = recent(key, nowMs);
  hits.delete(key);
  hits.set(key, [...list, nowMs]);
  while (hits.size > MAX_IPS) hits.delete(hits.keys().next().value);
}
