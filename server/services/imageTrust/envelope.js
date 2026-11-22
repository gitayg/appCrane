// The two signed formats, both standard and both checked against cosign v2.5.3
// (`verify-blob-attestation` and `verify-blob` with --key):
//
//   DSSE envelope (https://github.com/secure-systems-lab/dsse, v1) carrying an
//   in-toto Statement v1. The signature is over the Pre-Authentication Encoding
//   PAE(payloadType, payload), never over the bare JSON.
//
//   cosign "simple signing" payload for the image itself: the JSON object
//   cosign signs for a container image, signed directly (ECDSA P-256 SHA-256,
//   DER, base64).

import crypto from 'node:crypto';

export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const SIMPLE_SIGNING_TYPE = 'cosign container image signature';

export function pae(payloadType, payload) {
  const t = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${t.length} `, 'utf8'), t,
    Buffer.from(` ${payload.length} `, 'utf8'), payload,
  ]);
}

/** Sign an in-toto statement into a DSSE envelope. */
export function signStatement(statement, { privateKey, keyId }) {
  const payload = Buffer.from(JSON.stringify(statement), 'utf8');
  const sig = crypto.sign('sha256', pae(INTOTO_PAYLOAD_TYPE, payload), privateKey);
  return {
    payloadType: INTOTO_PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [{ keyid: keyId, sig: sig.toString('base64') }],
  };
}

/**
 * Verify a DSSE envelope against one public key.
 * @returns {{ ok: boolean, statement?: object, reason?: string }}
 */
export function verifyEnvelope(envelope, publicKey) {
  if (!envelope || envelope.payloadType !== INTOTO_PAYLOAD_TYPE || typeof envelope.payload !== 'string') {
    return { ok: false, reason: 'not an in-toto DSSE envelope' };
  }
  const payload = Buffer.from(envelope.payload, 'base64');
  const signed = (envelope.signatures || []).some((s) => {
    try { return crypto.verify('sha256', pae(envelope.payloadType, payload), publicKey, Buffer.from(String(s.sig), 'base64')); } catch { return false; }
  });
  if (!signed) return { ok: false, reason: 'no signature on the envelope verifies with this instance\'s key' };
  let statement;
  try { statement = JSON.parse(payload.toString('utf8')); } catch { return { ok: false, reason: 'the signed payload is not JSON' }; }
  if (statement?._type !== STATEMENT_TYPE) return { ok: false, reason: `the signed payload is not an in-toto Statement v1 (${statement?._type})` };
  return { ok: true, statement };
}

/** Does the statement name `digestHex` (sha256) among its subjects? */
export function statementCovers(statement, digestHex) {
  return Array.isArray(statement?.subject) && statement.subject.some((s) => s?.digest?.sha256 === digestHex);
}

/** The cosign simple-signing payload for an image, as the exact bytes that are signed. */
export function simpleSigningPayload({ repository, digest, annotations = {} }) {
  return Buffer.from(JSON.stringify({
    critical: {
      identity: { 'docker-reference': repository },
      image: { 'docker-manifest-digest': digest },
      type: SIMPLE_SIGNING_TYPE,
    },
    optional: annotations,
  }), 'utf8');
}

export function signBytes(bytes, privateKey) {
  return crypto.sign('sha256', bytes, privateKey).toString('base64');
}

export function verifyBytes(bytes, signatureB64, publicKey) {
  try { return crypto.verify('sha256', bytes, publicKey, Buffer.from(String(signatureB64), 'base64')); } catch { return false; }
}
