/**
 * Domain aliases (v2.24.4) — old domains that 301-redirect to an app's current
 * custom domain, so a domain migration never drops already-sent login links or
 * bookmarks. AppCrane owns the whole lifecycle: on a domain change it keeps the
 * old domain alive automatically; owners can also add/remove aliases manually.
 *
 * Shared by the REST route and the MCP set_app_meta tool so the two write paths
 * can't drift (same validation + auto-seed semantics).
 */
import { validateCustomDomain, isValidDomainFormat } from '../utils/customDomain.js';

export function listAliases(db, appId) {
  return db.prepare(
    'SELECT id, domain, source, created_at FROM app_domain_aliases WHERE app_id = ? ORDER BY created_at, id'
  ).all(appId);
}

/**
 * Is `domain` already claimed — as a primary domain OR an alias — by an app
 * other than `exceptAppId`? Returns { kind, slug } or null.
 */
function domainClaim(db, domain, exceptAppId) {
  const d = String(domain).trim().toLowerCase();
  const except = exceptAppId || -1;
  const primary = db.prepare('SELECT slug FROM apps WHERE lower(domain) = ? AND id != ?').get(d, except);
  if (primary) return { kind: 'primary', slug: primary.slug };
  const alias = db.prepare(
    `SELECT a.slug FROM app_domain_aliases da JOIN apps a ON a.id = da.app_id
     WHERE lower(da.domain) = ? AND da.app_id != ?`
  ).get(d, except);
  if (alias) return { kind: 'alias', slug: alias.slug };
  return null;
}

/**
 * Add a manual alias for `app`. Throws Error on invalid/clash. Idempotent for
 * the app's own aliases. Returns the row.
 */
export function addAlias(db, app, domainInput) {
  const domain = validateCustomDomain(domainInput, process.env.CRANE_DOMAIN);
  if (!domain) throw new Error('An alias domain is required.');
  if (app.domain && domain === String(app.domain).trim().toLowerCase()) {
    throw new Error(`"${domain}" is already this app's primary domain — nothing to redirect.`);
  }
  const existing = db.prepare('SELECT id, domain, source, created_at FROM app_domain_aliases WHERE app_id = ? AND lower(domain) = ?').get(app.id, domain);
  if (existing) return existing;
  const claim = domainClaim(db, domain, app.id);
  if (claim) throw new Error(`Domain "${domain}" is already used by app "${claim.slug}".`);
  const info = db.prepare("INSERT INTO app_domain_aliases (app_id, domain, source) VALUES (?, ?, 'manual')").run(app.id, domain);
  return db.prepare('SELECT id, domain, source, created_at FROM app_domain_aliases WHERE id = ?').get(info.lastInsertRowid);
}

export function removeAlias(db, app, aliasId) {
  return db.prepare('DELETE FROM app_domain_aliases WHERE id = ? AND app_id = ?').run(aliasId, app.id).changes > 0;
}

/**
 * On a primary-domain change X→Y, keep X working by seeding it as a redirect
 * alias to Y. Also drops any existing alias row equal to the new primary Y
 * (can't redirect Y→Y). Safe no-op when the domain was cleared, unchanged, or
 * the old domain is now claimed by another app.
 */
export function autoSeedAliasOnDomainChange(db, app, oldDomain, newDomain) {
  const oldD = (oldDomain || '').trim().toLowerCase();
  const newD = (newDomain || '').trim().toLowerCase();
  if (newD) {
    // The new primary can't also be one of this app's redirect aliases.
    db.prepare('DELETE FROM app_domain_aliases WHERE app_id = ? AND lower(domain) = ?').run(app.id, newD);
  }
  if (!oldD || !newD || oldD === newD) return;
  if (!isValidDomainFormat(oldD)) return;
  if (domainClaim(db, oldD, app.id)) return; // another app took the old domain — don't hijack it
  db.prepare("INSERT OR IGNORE INTO app_domain_aliases (app_id, domain, source) VALUES (?, ?, 'auto')").run(app.id, oldD);
}
