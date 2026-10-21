// tools/call arguments → the HTTP request AppCrane sends the app.
//
// Path parameters ({id}) are filled from the arguments of the same name,
// percent-encoded as one segment. The remaining arguments go in the query
// string for GET and DELETE and in a JSON body otherwise. Arguments are checked
// against the declared input_schema first (required, top-level types, and
// additionalProperties: false), so a malformed call fails here, not in the app.

export class ToolArgsError extends Error {}

function typeOk(type, v) {
  switch (type) {
    case 'string': return typeof v === 'string';
    case 'number': return typeof v === 'number' && Number.isFinite(v);
    case 'integer': return Number.isInteger(v);
    case 'boolean': return typeof v === 'boolean';
    case 'object': return v !== null && typeof v === 'object' && !Array.isArray(v);
    case 'array': return Array.isArray(v);
    case 'null': return v === null;
    default: return true;
  }
}

export function checkArgs(tool, args) {
  if (args === undefined || args === null) args = {};
  if (typeof args !== 'object' || Array.isArray(args)) throw new ToolArgsError('arguments must be an object');
  const schema = tool.input_schema || {};
  const props = schema.properties || {};
  for (const r of schema.required || []) {
    if (args[r] === undefined) throw new ToolArgsError(`missing required argument "${r}"`);
  }
  for (const [k, v] of Object.entries(args)) {
    const p = props[k];
    if (!p) {
      if (schema.additionalProperties === false) throw new ToolArgsError(`unknown argument "${k}"`);
      continue;
    }
    if (p.type && !typeOk(p.type, v)) throw new ToolArgsError(`argument "${k}" must be of type ${p.type}`);
  }
  return args;
}

function segmentValue(name, v) {
  if (typeof v !== 'string' && typeof v !== 'number') throw new ToolArgsError(`path argument "${name}" must be a string or number`);
  const s = String(v);
  if (s === '' || s === '.' || s === '..') throw new ToolArgsError(`path argument "${name}" must not be empty, "." or ".."`);
  return encodeURIComponent(s);
}

/** { method, path, body } — path includes the query string; body is a string or null. */
export function translate(tool, rawArgs) {
  const args = checkArgs(tool, rawArgs);
  const rest = { ...args };
  const path = tool.path.split('/').map((seg) => {
    const m = /^\{(.+)\}$/.exec(seg);
    if (!m) return seg;
    const v = segmentValue(m[1], args[m[1]]);
    delete rest[m[1]];
    return v;
  }).join('/');
  if (tool.method === 'GET' || tool.method === 'DELETE') {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(rest)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) for (const item of v) qs.append(k, typeof item === 'object' ? JSON.stringify(item) : String(item));
      else qs.append(k, v !== null && typeof v === 'object' ? JSON.stringify(v) : String(v));
    }
    const q = qs.toString();
    return { method: tool.method, path: q ? `${path}?${q}` : path, pathOnly: path, body: null };
  }
  return { method: tool.method, path, pathOnly: path, body: JSON.stringify(rest) };
}

/** The template with every {param} replaced, for checking path rules when listing. */
export function placeholderPath(tool) {
  return tool.path.replace(/\{[^}]+\}/g, '_');
}
