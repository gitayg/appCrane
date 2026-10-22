// Is this OSV advisory a remote-code-execution advisory? Decides which fixes
// the auto-patch policy may approve without a person.
//
// Input is the hydrated OSV record (/v1/vulns/<id>). The stored scan findings
// carry only {name, version, ecosystem, ids, fixed}, so the CWE ids and the
// text are read from OSV, never guessed from the finding.
//
// Two signals, either one is enough:
//   1. database_specific.cwe_ids (GitHub advisories) names a CWE whose
//      consequence is code or command execution.
//   2. summary or details says so in words ("remote code execution", "RCE",
//      "arbitrary code execution", "execute arbitrary commands", ...).
//
// Excluded unless the text says code execution:
//   CWE-1321 prototype pollution: GitHub tags hundreds of advisories with it
//            whose impact is denial of service or property injection (the
//            lodash and minimist advisories measured had no execution claim).
//   CWE-434  unrestricted upload: execution depends on how the host serves
//            the file, which the advisory rarely states.
//   CWE-74   generic injection: too broad (header, log and XSS injection).
// XSS (CWE-79), ReDoS (CWE-1333), SSRF (CWE-918) and open redirect (CWE-601)
// are never RCE by CWE.
//
// A withdrawn advisory is never RCE: OSV says "If the field is missing, then
// the entry has not been withdrawn."

export const RCE_CWES = Object.freeze([
  'CWE-77',   // command injection
  'CWE-78',   // OS command injection
  'CWE-94',   // code injection
  'CWE-95',   // eval injection
  'CWE-502',  // deserialization of untrusted data
  'CWE-917',  // expression language injection
  'CWE-1336', // template engine injection (SSTI)
]);

export const RCE_TEXT = Object.freeze([
  /\bremote code execution\b/i,
  /\barbitrary code execution\b/i,
  /\bcode execution\b/i,
  /\bcommand execution\b/i,
  /\bexecut(?:e|ion of) arbitrary (?:code|commands?|javascript|js|shell commands?)\b/i,
  /\bRCE\b/,
]);

/**
 * @param {object} record hydrated OSV advisory
 * @returns {{ rce: boolean, cwe_hits: string[], text_hits: string[], withdrawn: boolean, reason: string }}
 */
export function classifyAdvisory(record) {
  if (!record || typeof record !== 'object') {
    return { rce: false, cwe_hits: [], text_hits: [], withdrawn: false, reason: 'no advisory record' };
  }
  const withdrawn = typeof record.withdrawn === 'string' && record.withdrawn !== '';
  const cwes = Array.isArray(record.database_specific?.cwe_ids)
    ? record.database_specific.cwe_ids.map((c) => String(c).toUpperCase().trim())
    : [];
  const cweHits = cwes.filter((c) => RCE_CWES.includes(c));
  const text = `${record.summary || ''}\n${record.details || ''}`;
  const textHits = RCE_TEXT.filter((re) => re.test(text)).map((re) => re.source);
  if (withdrawn) {
    return { rce: false, cwe_hits: cweHits, text_hits: textHits, withdrawn, reason: `advisory withdrawn ${record.withdrawn}` };
  }
  const rce = cweHits.length > 0 || textHits.length > 0;
  const reason = rce
    ? [cweHits.length ? `CWE ${cweHits.join(', ')}` : null, textHits.length ? 'the advisory text says code execution' : null].filter(Boolean).join(' and ')
    : `not a code-execution advisory (CWE ${cwes.join(', ') || 'none'})`;
  return { rce, cwe_hits: cweHits, text_hits: textHits, withdrawn, reason };
}
