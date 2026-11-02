// Whether any platform admin exists — the setup guard asks on every request.
// Only the positive answer is remembered: no code path removes the last
// platform admin (self-delete and self-demote are refused, demoting the only
// one is refused, SCIM deletes only role='user'), so once true it stays true.
// A false answer is re-read each time so `crane init` takes effect at once.
let known = false;

export function adminExists(db) {
  if (known) return true;
  known = db.prepare("SELECT 1 FROM users WHERE role = 'platform_admin' LIMIT 1").get() !== undefined;
  return known;
}
