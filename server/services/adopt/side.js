// Which side of the wire a file runs on, as far as its path and its own
// directives say. "client" means it ends up in a bundle every visitor
// downloads, which is what turns a server secret in it into a published one.

const SERVER_DIRS = /^(?:server|api|backend|functions|lib\/server|src\/server|src\/api|app\/api|src\/app\/api|pages\/api|src\/pages\/api)\//;
const CLIENT_DIRS = /^(?:client|frontend|web|public|src|app|components|pages|lib|hooks|utils|styles)\//;

export function fileSide(path, text, project) {
  if (path.startsWith('supabase/functions/')) return 'edge';
  if (/(?:^|\/)\.env/.test(path)) return 'env';
  if (/(?:^|\/)(?:vite|next|tailwind|postcss|eslint|tsconfig|jest|vitest)\.config\.|(?:^|\/)tsconfig.*\.json$/.test(path)) return 'config';
  if (/\.py$/.test(path)) return 'server';
  if (/^\s*['"]use server['"]/m.test(text || '')) return 'server';
  if (/^\s*['"]use client['"]/m.test(text || '')) return 'client';
  if (SERVER_DIRS.test(path)) return 'server';
  if (/\.server\.[cm]?[jt]sx?$/.test(path)) return 'server';
  if (path === 'index.html' || /\.html?$/.test(path)) return 'client';
  const kind = project?.kind;
  if (kind === 'spa' || kind === 'static') return /\.(?:[cm]?[jt]sx?|vue|svelte|html?)$/.test(path) ? 'client' : 'other';
  if (kind === 'server' && project.framework === 'node-server') {
    return /^(?:client|frontend|web|src\/client)\//.test(path) ? 'client' : 'server';
  }
  if (kind === 'ssr') {
    if (/\.client\.[cm]?[jt]sx?$/.test(path)) return 'client';
    return CLIENT_DIRS.test(path) ? 'shared' : 'server';
  }
  return CLIENT_DIRS.test(path) ? 'shared' : 'other';
}

export const BUNDLED_SIDES = new Set(['client', 'shared']);
