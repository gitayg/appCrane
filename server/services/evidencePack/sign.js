import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { deriveSecret } from '../encryption.js';

// The pack's manifest lists every file with its SHA-256; manifest.sig is an
// HMAC-SHA256 of the exact manifest.json bytes under a key derived from the
// instance ENCRYPTION_KEY with a label used for nothing else. Anyone can
// recompute the file hashes; only this instance (or one holding its key) can
// confirm the signature.

export const KEY_LABEL = 'appcrane-evidence-pack-manifest-v1';
export const MANIFEST_FILE = 'manifest.json';
export const SIG_FILE = 'manifest.sig';

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export function signManifest(manifestBytes) {
  return createHmac('sha256', Buffer.from(deriveSecret(KEY_LABEL), 'hex')).update(manifestBytes).digest('hex');
}

/**
 * Verify a pack given as { relativePath: Buffer }. Returns a result object;
 * never throws for a bad pack.
 */
export function verifyFiles(files) {
  const out = { ok: false, signature_ok: false, manifest_ok: false, files: [], missing: [], unexpected: [], errors: [] };
  const mBytes = files[MANIFEST_FILE];
  const sig = files[SIG_FILE];
  if (!mBytes) { out.errors.push('manifest.json is missing'); return out; }
  if (!sig) out.errors.push('manifest.sig is missing');
  else {
    const want = Buffer.from(signManifest(mBytes), 'hex');
    const got = Buffer.from(String(sig).trim(), 'hex');
    out.signature_ok = got.length === want.length && timingSafeEqual(got, want);
    if (!out.signature_ok) out.errors.push('the manifest signature does not match: the manifest was changed, or the pack was not produced with this instance key');
  }
  let manifest;
  try { manifest = JSON.parse(mBytes.toString('utf8')); } catch (_) { out.errors.push('manifest.json is not valid JSON'); return out; }
  if (manifest?.kind !== 'appcrane-evidence-pack' || !Array.isArray(manifest.files)) { out.errors.push('not an AppCrane evidence pack manifest'); return out; }
  out.manifest_ok = true;
  out.pack_id = manifest.pack_id || null;
  out.period = manifest.period || null;
  out.generated_at = manifest.generated_at || null;
  const listed = new Set();
  for (const f of manifest.files) {
    listed.add(f.path);
    const buf = files[f.path];
    if (!buf) { out.missing.push(f.path); continue; }
    const ok = sha256(buf) === f.sha256 && buf.length === f.bytes;
    out.files.push({ path: f.path, ok });
    if (!ok) out.errors.push(`${f.path} does not match its manifest hash`);
  }
  for (const p of Object.keys(files)) {
    if (p !== MANIFEST_FILE && p !== SIG_FILE && !listed.has(p)) out.unexpected.push(p);
  }
  if (out.missing.length) out.errors.push(`${out.missing.length} listed file(s) missing`);
  if (out.unexpected.length) out.errors.push(`${out.unexpected.length} file(s) not in the manifest`);
  out.ok = out.signature_ok && out.manifest_ok && !out.missing.length && !out.unexpected.length && out.files.every((f) => f.ok);
  return out;
}
