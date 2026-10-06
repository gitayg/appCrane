// Mapping an SSO identity to a local account (security audit 2026-10-06, M4).
//
// OIDC and SAML both linked a local account by e-mail: no email_verified check,
// and an account already bound to one SSO identity was re-bound to whichever
// identity next asserted its e-mail. Any IdP identity able to claim a victim's
// address (including a platform admin's) became that victim. One rule for both:
//
//  - the stable subject (OIDC `sub`, SAML NameID) is the key;
//  - an account found only by e-mail is linked once, and only if it has no SSO
//    identity of this kind yet: a bound account is NEVER moved to another one;
//  - for OIDC the e-mail must be verified by the IdP (email_verified: true),
//    unless the operator opts out for an IdP that never sends the claim
//    (OIDC_ALLOW_UNVERIFIED_EMAIL_LINK=1). SAML assertions are signed by the
//    IdP as a whole, so their e-mail counts as verified.

const COLUMNS = new Set(['sso_sub', 'saml_name_id']);

function refuse(message, popupCode) {
  const err = new Error(message);
  err.popupCode = popupCode;
  return err;
}

/**
 * The local account for this SSO identity, linking by e-mail when allowed.
 * Returns null when no account matches (the caller may auto-provision).
 * Throws when an account matches by e-mail but may not be linked.
 */
export function findOrLinkSsoUser(db, { column, subject, email, emailVerified, allowUnverified = false }) {
  if (!COLUMNS.has(column)) throw new Error(`findOrLinkSsoUser: unknown column ${column}`);
  if (!subject) throw new Error('findOrLinkSsoUser: no subject');
  const bySubject = db.prepare(`SELECT * FROM users WHERE ${column} = ?`).get(subject);
  if (bySubject) return bySubject;
  if (!email) return null;

  const byEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!byEmail) return null;
  if (byEmail[column] && byEmail[column] !== subject) {
    throw refuse(`The account for ${email} is already linked to a different SSO identity; it is not moved. Ask an administrator.`, 'sso_identity_conflict');
  }
  if (!emailVerified && !allowUnverified) {
    throw refuse(`The identity provider did not verify ${email}, so it is not linked to the existing account. Ask an administrator.`, 'sso_email_unverified');
  }
  db.prepare(`UPDATE users SET ${column} = ? WHERE id = ? AND ${column} IS NULL`).run(subject, byEmail.id);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(byEmail.id);
}
