import { fileURLToPath } from 'url';

// Modules other features ship, loaded only if present. A missing module, or
// one without the expected export, degrades its evidence file to a statement
// of what is absent instead of failing the pack.

export const OPTIONAL = {
  accessReviews: { specs: ['../accessReviews/index.js', '../accessReviews/evidence.js', '../accessReviews.js'], exports: ['getAccessReviewEvidence'] },
  auditChain: { specs: ['../auditChain.js'], exports: ['verifyAuditChain', 'verifyChain', 'verify'] },
  releaseCheck: { specs: ['../releaseCheck.js'], exports: ['listReleaseChecks', 'CHECK_IDS'] },
  siem: { specs: ['../siem/delivery.js'], exports: ['sinkHealth'] },
};

let overrides = null;
/** Tests: { name: module object | null }. null = the module is absent. */
export function _setOptionalModulesForTests(map) { overrides = map; }

/** { mod, fn, name } for the first spec that loads and exports one of the names, or { reason }. */
export async function loadOptional(name) {
  const def = OPTIONAL[name];
  if (overrides && Object.prototype.hasOwnProperty.call(overrides, name)) {
    const mod = overrides[name];
    if (!mod) return { reason: 'module not installed' };
    const fnName = def.exports.find((e) => mod[e] !== undefined);
    return fnName ? { mod, fn: mod[fnName], name: fnName } : { reason: `module has none of: ${def.exports.join(', ')}` };
  }
  let lastReason = 'module not installed';
  for (const spec of def.specs) {
    let mod;
    try {
      mod = await import(spec);
    } catch (e) {
      const self = e?.code === 'ERR_MODULE_NOT_FOUND' && String(e.message).includes(fileURLToPath(new URL(spec, import.meta.url)));
      if (!self) lastReason = `module failed to load: ${String(e.message).split('\n')[0].slice(0, 160)}`;
      continue;
    }
    const fnName = def.exports.find((e) => mod[e] !== undefined);
    if (fnName) return { mod, fn: mod[fnName], name: fnName };
    lastReason = `module has none of: ${def.exports.join(', ')}`;
  }
  return { reason: lastReason };
}
