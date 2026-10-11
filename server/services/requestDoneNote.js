/**
 * The optional "what was done" note a closer attaches when a request reaches
 * done / won't-do. It is user-supplied text that ends up in an email body, so it
 * is cleaned in one place for every entry point (REST bucket, REST set-status,
 * MCP) rather than three slightly different ways.
 */

export const DONE_NOTE_MAX = 2000;

// C0 controls and DEL, minus \n. Plain-text mail needs no HTML escaping, but a
// stray \r, \b or escape sequence can still mangle how a client renders the
// body or let the note fake extra lines, so only real newlines survive.
const CONTROL_RE = /[\u0000-\u0009\u000B-\u001F\u007F]/g;

export function stripNoteControls(s) {
  return String(s).replace(/\r\n?/g, '\n').replace(CONTROL_RE, '');
}

/**
 * Returns the cleaned note, or null when there is none (undefined, null, or
 * empty after trimming). Throws a NoteError the caller turns into a 400 / tool
 * error: a silently truncated note would tell the requester half a story.
 */
export function cleanDoneNote(raw) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string') throw new NoteError('note must be a string');
  const note = stripNoteControls(raw).trim();
  if (!note) return null;
  if (note.length > DONE_NOTE_MAX) {
    throw new NoteError(`note must be at most ${DONE_NOTE_MAX} characters (got ${note.length})`);
  }
  return note;
}

export class NoteError extends Error {}

const TERMINAL = new Set(['done', 'no_changes_needed']);

/**
 * Write the note as part of a status write. On a real transition into a
 * terminal state the note always replaces the old one, even with null, so a
 * request that was reopened and shipped again does not mail out the previous
 * round's explanation. Re-marking a request that is already in that state only
 * replaces the note when a new one is given, so a repeat click with an empty box
 * does not erase it.
 */
export function writeDoneNote(db, id, prevStatus, newStatus, note) {
  if (!TERMINAL.has(newStatus)) return;
  if (prevStatus === newStatus && note == null) return;
  db.prepare('UPDATE enhancement_requests SET done_note = ? WHERE id = ?').run(note, id);
}
