import { parseDotenv } from '../dotenvParse.js';
import { isEnvFile, isEnvTemplate, scannable } from './projectFiles.js';
import { fileSide } from './side.js';

// Environment variables the project reads, found by reading source and env
// templates. Values from a real .env shipped in an upload are kept apart: they
// are secrets, returned only as "a value was found", and never logged.

const PLATFORM_PROVIDED = new Set([
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'MODE', 'DEV', 'PROD', 'SSR', 'BASE_URL', 'APP_BASE_PATH', 'PUBLIC_URL',
  'VITE_BASE_PATH', 'DATA_DIR', 'FE_PORT', 'CRANE_URL', 'CRANE_INTERNAL_URL', 'CI', 'PWD', 'HOME', 'PATH', 'TZ',
  'VERCEL', 'VERCEL_URL', 'VERCEL_ENV', 'NETLIFY', 'REPL_ID', 'REPL_SLUG', 'REPL_OWNER', 'REPLIT_DEV_DOMAIN', 'REPLIT_DOMAINS',
  'NEXT_RUNTIME', 'npm_package_version', 'npm_lifecycle_event',
]);

const KEY = '([A-Za-z_][A-Za-z0-9_]*)';
const PATTERNS = [
  new RegExp(`import\\.meta\\.env\\.${KEY}`, 'g'),
  new RegExp(`import\\.meta\\.env\\[["'\`]${KEY}["'\`]\\]`, 'g'),
  new RegExp(`process\\.env\\.${KEY}`, 'g'),
  new RegExp(`process\\.env\\[["'\`]${KEY}["'\`]\\]`, 'g'),
  new RegExp(`os\\.environ\\[["']${KEY}["']\\]`, 'g'),
  new RegExp(`os\\.environ\\.get\\(\\s*["']${KEY}["']`, 'g'),
  new RegExp(`os\\.getenv\\(\\s*["']${KEY}["']`, 'g'),
  new RegExp(`Deno\\.env\\.get\\(\\s*["']${KEY}["']`, 'g'),
];
const DESTRUCTURE = /const\s*\{([^}]{1,400})\}\s*=\s*(?:process\.env|import\.meta\.env)/g;

export function isPublicPrefix(key) {
  return /^(?:VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)/.test(key);
}

function hintFor(key) {
  if (/SUPABASE.*URL/.test(key)) return 'Your Supabase project URL (Project Settings > API).';
  if (/SUPABASE.*(?:SERVICE_ROLE|SECRET)/.test(key)) return 'Supabase service-role / secret key. Server only, never in client code.';
  if (/SUPABASE.*(?:ANON|PUBLISHABLE)/.test(key)) return 'Supabase anon / publishable key (public by design; access is governed by Row Level Security).';
  if (/SUPABASE.*PROJECT_ID/.test(key)) return 'Your Supabase project ref.';
  if (/DATABASE_URL|POSTGRES|PG(?:HOST|USER|PASSWORD|DATABASE)/.test(key)) return 'Database connection. Keep the external database or use an AppCrane managed Postgres.';
  if (/OPENAI|ANTHROPIC|GEMINI|GROQ|MISTRAL/.test(key)) return 'Model provider API key.';
  if (/STRIPE/.test(key)) return 'Stripe key; use a test-mode key in the sandbox.';
  if (/FIREBASE/.test(key)) return 'Firebase web config value.';
  if (/CLERK/.test(key)) return 'Clerk key. Behind AppCrane SSO you may not need Clerk.';
  if (/AUTH0/.test(key)) return 'Auth0 setting. Behind AppCrane SSO you may not need Auth0.';
  return null;
}

/**
 * { vars: [{ key, scope, build_time, sources, in_template, value_in_upload, hint }], uploaded_values }
 * uploaded_values maps key -> value from .env files in the upload (never sent to a client).
 */
export function scanEnv(files, project) {
  const found = new Map();
  const touch = (key, path, side) => {
    if (PLATFORM_PROVIDED.has(key)) return;
    let v = found.get(key);
    if (!v) { v = { key, sides: new Set(), sources: new Set(), in_template: false, value_in_upload: false }; found.set(key, v); }
    if (path) v.sources.add(path);
    if (side) v.sides.add(side);
    return v;
  };

  const uploadedValues = {};
  for (const [path, text] of scannable(files)) {
    if (isEnvFile(path)) {
      const pairs = (() => { try { return [...parseDotenv(text).values]; } catch { return []; } })();
      for (const [key, value] of pairs) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(key))) continue;
        const v = touch(key, null, null);
        if (!v) continue;
        if (isEnvTemplate(path)) v.in_template = true;
        else if (typeof value === 'string' && value !== '') { v.value_in_upload = true; uploadedValues[key] = value; }
      }
      continue;
    }
    if (!/\.(?:[cm]?[jt]sx?|vue|svelte|astro|py|html?)$/.test(path)) continue;
    const side = fileSide(path, text, project);
    for (const re of PATTERNS) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) touch(m[1], path, side);
    }
    for (const m of text.matchAll(DESTRUCTURE)) {
      for (const part of m[1].split(',')) {
        const k = part.split(/[:=]/)[0].trim();
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) touch(k, path, side);
      }
    }
  }

  const vars = [...found.values()].map((v) => {
    const sides = [...v.sides];
    const edgeOnly = sides.length > 0 && sides.every((s) => s === 'edge');
    const client = isPublicPrefix(v.key) || sides.includes('client');
    return {
      key: v.key,
      scope: edgeOnly ? 'supabase-edge' : client ? 'client' : 'server',
      build_time: !edgeOnly && (isPublicPrefix(v.key) || (project?.kind === 'spa' && client)),
      sources: [...v.sources].slice(0, 5),
      in_template: v.in_template,
      value_in_upload: v.value_in_upload,
      hint: hintFor(v.key),
    };
  }).sort((a, b) => (a.scope === b.scope ? a.key.localeCompare(b.key) : a.scope.localeCompare(b.scope)));
  return { vars, uploaded_values: uploadedValues };
}
