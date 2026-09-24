// Files a user pastes, drops or picks into a coder message.
//
// Stored on the host per session under an opaque id, copied into the app
// container when the turn that uses them runs, and named to the agent by path.
// Claude Code's Read tool reads text, code, images and PDFs from a path, so a
// file needs no special encoding in the prompt.
//
// Nothing here reaches a shell: ids are server-generated and checked against a
// strict pattern, the stored name is reduced to a safe character set, and the
// copy goes through execFileSync argv. The prompt that names the path is
// passed after `--` and quoted (runAgent.js).

import { execFileSync } from 'child_process';
import { mkdirSync, readdirSync, writeFileSync, readFileSync } from 'fs';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { attachmentsDirFor } from './appContainer.js';

export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
export const MAX_ATTACHMENTS_PER_MESSAGE = 10;
export const CONTAINER_ATTACHMENTS_DIR = '/tmp/appcrane-attachments';

const ID_RE = /^[A-Za-z0-9_-]{22}$/;

/** A name that is safe as a file name and still tells the agent what the file is. */
export function safeAttachmentName(name) {
  const base = String(name || '').split(/[\\/]/).pop() || '';
  const cleaned = base.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._]+/, '').slice(-80);
  return cleaned || 'file';
}

function isImage(buf) {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return true;
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return true;
  if (buf.length >= 6 && (buf.subarray(0, 6).toString('latin1') === 'GIF87a' || buf.subarray(0, 6).toString('latin1') === 'GIF89a')) return true;
  if (buf.length >= 12 && buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return true;
  return false;
}

/** Store one uploaded file. `data` is base64. Returns the public descriptor. */
export function saveAttachment(slug, sessionId, { name, data }) {
  if (typeof data !== 'string' || !data) {
    throw Object.assign(new Error('data (base64) is required'), { code: 'VALIDATION', status: 400 });
  }
  const buf = Buffer.from(data, 'base64');
  if (!buf.length) throw Object.assign(new Error('The file is empty'), { code: 'VALIDATION', status: 400 });
  if (buf.length > MAX_ATTACHMENT_BYTES) {
    throw Object.assign(new Error(`The file is ${(buf.length / 1048576).toFixed(1)} MB; the limit is ${MAX_ATTACHMENT_BYTES / 1048576} MB`),
      { code: 'TOO_LARGE', status: 413 });
  }
  const id = randomBytes(16).toString('base64url');
  const safeName = safeAttachmentName(name);
  const dir = attachmentsDirFor(slug, sessionId);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${id}__${safeName}`), buf, { mode: 0o644 });
  return { id, name: safeName, size: buf.length, is_image: isImage(buf) };
}

/**
 * Turn ids from a request into stored files of THIS session. An id from another
 * session, or one that was never issued, is refused rather than skipped: a
 * message that silently lost its screenshot is worse than one that says so.
 */
export function resolveAttachments(slug, sessionId, ids) {
  if (ids == null) return [];
  if (!Array.isArray(ids)) throw Object.assign(new Error('attachments must be a list of ids'), { code: 'VALIDATION', status: 400 });
  if (ids.length > MAX_ATTACHMENTS_PER_MESSAGE) {
    throw Object.assign(new Error(`At most ${MAX_ATTACHMENTS_PER_MESSAGE} files per message`), { code: 'VALIDATION', status: 400 });
  }
  if (!ids.length) return [];
  const dir = attachmentsDirFor(slug, sessionId);
  let entries = [];
  try { entries = readdirSync(dir); } catch (_) {}
  return ids.map((id) => {
    if (typeof id !== 'string' || !ID_RE.test(id)) {
      throw Object.assign(new Error('Invalid attachment id'), { code: 'VALIDATION', status: 400 });
    }
    const file = entries.find((e) => e.startsWith(`${id}__`));
    if (!file) throw Object.assign(new Error('Attachment not found for this session. Attach the file again.'), { code: 'NOT_FOUND', status: 404 });
    const name = file.slice(id.length + 2);
    return { id, name, file, is_image: isImage(readFileSync(join(dir, file)).subarray(0, 12)) };
  });
}

/** Copy a turn's attachments into the container; returns the paths the agent will read. */
export function copyAttachmentsIntoContainer(containerId, slug, sessionId, attachments) {
  if (!attachments?.length) return [];
  execFileSync('docker', ['exec', containerId, 'mkdir', '-p', CONTAINER_ATTACHMENTS_DIR], { stdio: 'pipe', timeout: 15000 });
  const dir = attachmentsDirFor(slug, sessionId);
  return attachments.map((a) => {
    const target = `${CONTAINER_ATTACHMENTS_DIR}/${a.file}`;
    execFileSync('docker', ['cp', join(dir, a.file), `${containerId}:${target}`], { stdio: 'pipe', timeout: 30000 });
    return { ...a, path: target };
  });
}

/** The part of the prompt that tells the agent what was attached and where. */
export function attachmentsPromptSection(copied) {
  if (!copied?.length) return '';
  const lines = copied.map((a) => `- ${a.path}${a.is_image ? ' (image)' : ''}`);
  return `\n\n# Attached files\nThe user attached these files to this message. Read them with the Read tool, which can also view images and PDFs:\n${lines.join('\n')}`;
}
