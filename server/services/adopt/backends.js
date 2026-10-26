import { allDeps, hasDir, jsonOf, scannable } from './projectFiles.js';

// Hosted services the project depends on. These keep working from AppCrane as
// long as their keys are set; the report says which of them AppCrane can
// replace (sign-in, databases) and which stay external.

const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co/g;

export function detectBackends(files) {
  const pkg = jsonOf(files, 'package.json');
  const deps = allDeps(pkg);
  const supa = {
    used: false, client_library: !!(deps['@supabase/supabase-js'] || deps['@supabase/ssr'] || deps['@supabase/auth-helpers-nextjs']),
    project_refs: new Set(), auth: false, auth_methods: new Set(), database: false, tables: new Set(), storage: false,
    realtime: false, rpc: false, edge_functions: hasDir(files, 'supabase/functions'), migrations: hasDir(files, 'supabase/migrations'),
    hardcoded_url: false, client_files: new Set(),
  };
  const firebase = { used: !!(deps.firebase || deps['firebase-admin']), auth: false, firestore: false, storage: false };
  const clerk = { used: Object.keys(deps).some((d) => d.startsWith('@clerk/')) };
  const auth0 = { used: Object.keys(deps).some((d) => d.startsWith('@auth0/')) };
  const nextAuth = { used: !!(deps['next-auth'] || deps['@auth/core']) };
  const databases = new Set();
  if (deps.pg || deps.postgres || deps['@neondatabase/serverless'] || deps['@vercel/postgres']) databases.add('postgres');
  if (deps['drizzle-orm']) databases.add('drizzle');
  if (deps['@prisma/client'] || deps.prisma) databases.add('prisma');
  if (deps.mongodb || deps.mongoose) databases.add('mongodb');
  if (deps.mysql2 || deps.mysql) databases.add('mysql');
  if (deps['better-sqlite3'] || deps.sqlite3) databases.add('sqlite');
  if (deps.redis || deps.ioredis || deps['@upstash/redis']) databases.add('redis');
  const ai = new Set();
  for (const [d, name] of [['openai', 'OpenAI'], ['@anthropic-ai/sdk', 'Anthropic'], ['@google/generative-ai', 'Google Gemini'], ['@google/genai', 'Google Gemini'], ['ai', 'Vercel AI SDK'], ['groq-sdk', 'Groq']]) {
    if (deps[d]) ai.add(name);
  }

  for (const [path, text] of scannable(files)) {
    if (!/\.(?:[cm]?[jt]sx?|vue|svelte|py|html?)$/.test(path)) continue;
    if (path.startsWith('supabase/functions/')) continue;
    if (/@supabase\/supabase-js|createClient\s*\(|supabase\.co/.test(text)) {
      for (const m of text.matchAll(SUPABASE_URL_RE)) { supa.project_refs.add(m[1]); supa.hardcoded_url = true; }
      if (/createClient\s*\(|createBrowserClient\s*\(|createServerClient\s*\(/.test(text) && /supabase/i.test(text)) supa.client_files.add(path);
    }
    if (/\bsupabase\b/.test(text)) {
      if (/\.auth\.(?:signIn|signUp|signOut|getUser|getSession|onAuthStateChange|resetPasswordForEmail|exchangeCodeForSession)/.test(text)) {
        supa.auth = true;
        for (const m of text.matchAll(/\.auth\.(signInWithPassword|signInWithOAuth|signInWithOtp|signUp|signInWithIdToken)/g)) supa.auth_methods.add(m[1]);
      }
      for (const m of text.matchAll(/\.from\(\s*["'`]([A-Za-z0-9_]+)["'`]\s*\)\s*\.\s*(?:select|insert|update|upsert|delete)/g)) {
        supa.database = true; supa.tables.add(m[1]);
      }
      if (/\.storage\s*\.from\(/.test(text)) supa.storage = true;
      if (/\.channel\(|\.on\(\s*["']postgres_changes/.test(text)) supa.realtime = true;
      if (/\.rpc\(/.test(text)) { supa.rpc = true; supa.database = true; }
    }
    if (firebase.used) {
      if (/getAuth\(|signInWith(?:Popup|Redirect|EmailAndPassword)/.test(text)) firebase.auth = true;
      if (/getFirestore\(|collection\(/.test(text)) firebase.firestore = true;
      if (/getStorage\(/.test(text)) firebase.storage = true;
    }
  }
  supa.used = supa.client_library || supa.client_files.size > 0 || supa.migrations || supa.edge_functions;

  return {
    supabase: {
      ...supa,
      project_refs: [...supa.project_refs],
      auth_methods: [...supa.auth_methods],
      tables: [...supa.tables].slice(0, 50),
      client_files: [...supa.client_files].slice(0, 10),
    },
    firebase, clerk, auth0, next_auth: nextAuth,
    databases: [...databases],
    ai_providers: [...ai],
  };
}
