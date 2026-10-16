// What an app slug may SAY, as opposed to where it may route (slugPolicy.js).
//
// Two lists, matched against the slug's dash-separated tokens after
// normalising common evasions (digits for letters, stretched letters, letters
// split by dashes):
//
//   OFFENSIVE     profanity, slurs, abuse. Refused for everyone.
//   IMPERSONATION words that read as an AppCrane page or a trust signal on a
//                 URL that sits under the platform's own host. Refused for
//                 everyone except platform admins, who are the platform.
//
// Tokens, not substrings, so ordinary words that merely contain a sequence
// ("class", "assess", "scunthorpe", "therapist", "cockpit") stay allowed. Only
// SUBSTRING_TERMS are matched anywhere in the slug: terms no ordinary English
// word contains, so the substring match costs no false positives and catches
// run-together slugs.
//
// The matched word is never returned: callers get a category, and the message
// they show does not repeat it.

const OFFENSIVE = [
  'anal', 'arse', 'arsehole', 'ass', 'asses', 'asshole', 'assholes', 'bastard', 'bitch', 'bitches',
  'bollocks', 'boner', 'boobs', 'bullshit', 'chink', 'cock', 'cocks', 'coon', 'cunt', 'cunts',
  'dick', 'dickhead', 'dicks', 'dildo', 'dyke', 'fag', 'fags', 'faggot', 'fuck', 'fucker', 'fucking',
  'gook', 'handjob',
  'hitler', 'jizz', 'kike', 'kkk', 'molest', 'nazi', 'nazis', 'nigga', 'nigger', 'paki', 'pedo',
  'pedophile', 'piss', 'porn', 'prick', 'pussy', 'rape', 'raped', 'rapes', 'rapist', 'retard',
  'retarded', 'sex', 'shit', 'shits', 'shitty', 'shithead', 'slut', 'sluts', 'spic', 'tits',
  'titty', 'tranny', 'twat', 'wank', 'wanker', 'wetback', 'whore', 'whores',
];

// Matched anywhere in the slug with its dashes removed. Each is a term no
// ordinary word contains — except the words in SUBSTRING_ALLOW, which are
// taken out before the check ("snigger" contains a slur).
const SUBSTRING_TERMS = [
  'fuck', 'nigger', 'faggot', 'cocksuck', 'pedophil', 'wetback', 'whore', 'porn', 'bullshit',
  'dickhead', 'shithead', 'jizz',
];
const SUBSTRING_ALLOW = ['snigger'];

const IMPERSONATION = [
  'admin', 'administrator', 'sysadmin', 'superuser', 'root', 'system', 'login', 'logon', 'logout',
  'signin', 'signon', 'signup', 'auth', 'oauth', 'sso', 'saml', 'mfa', 'otp', 'password',
  'passwd', 'credentials', 'verify', 'verification', 'secure', 'support', 'helpdesk', 'billing',
  'payment', 'payments', 'appcrane', 'official',
];
const IMPERSONATION_SUBSTRINGS = ['appcrane'];

const LEET = { 0: 'o', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 9: 'g' };

/** Every reading of `s` with digits as letters. `1` is either i or l. */
function readings(s) {
  const base = [...s].map(c => LEET[c] ?? c).join('');
  return base.includes('1') ? [base.replaceAll('1', 'i'), base.replaceAll('1', 'l')] : [base];
}

const capRuns = (s, n) => s.replace(/(.)\1+/g, (run, c) => c.repeat(Math.min(run.length, n)));

/** The candidate words of a slug: its tokens, adjacent pairs joined, and runs of single letters joined. */
function candidates(slug) {
  const tokens = slug.split('-').filter(Boolean);
  const out = [...tokens];
  for (let i = 0; i + 1 < tokens.length; i++) out.push(tokens[i] + tokens[i + 1]);
  let run = '';
  for (const t of [...tokens, '']) {
    if (t.length === 1) { run += t; continue; }
    if (run.length > 1) out.push(run);
    run = '';
  }
  return out;
}

// A word matches a term as typed, with stretched letters capped at two
// ("asss" -> "ass"), or collapsed to one ("fuuuck" -> "fuck"). The list holds
// terms as spelled, so a collapsed form can only ever equal a term that has no
// doubled letter of its own: "boobs" is never shortened into "bobs".
function tokenHit(slug, set) {
  for (const word of candidates(slug)) {
    for (const r of readings(word)) {
      if (set.has(r) || set.has(capRuns(r, 2)) || set.has(capRuns(r, 1))) return true;
    }
  }
  return false;
}

function substringHit(slug, terms, allow = []) {
  const joined = slug.replaceAll('-', '');
  for (const r of readings(joined)) {
    let f = capRuns(r, 2);
    for (const a of allow) f = f.replaceAll(a, '');
    if (terms.some(t => f.includes(t))) return true;
  }
  return false;
}

const OFFENSIVE_SET = new Set(OFFENSIVE);
const IMPERSONATION_SET = new Set(IMPERSONATION);

/** 'offensive', 'impersonation', or null. */
export function slugContentCategory(slug) {
  if (typeof slug !== 'string' || !slug) return null;
  const s = slug.toLowerCase();
  if (tokenHit(s, OFFENSIVE_SET) || substringHit(s, SUBSTRING_TERMS, SUBSTRING_ALLOW)) return 'offensive';
  if (tokenHit(s, IMPERSONATION_SET) || substringHit(s, IMPERSONATION_SUBSTRINGS)) return 'impersonation';
  return null;
}
