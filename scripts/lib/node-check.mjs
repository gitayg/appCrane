export const NODE_FIX = 'run `nvm use` or PATH=/usr/local/bin:$PATH';

export function nodeProblem({ required, version, loadError }) {
  const major = Number(String(version).replace(/^v/, '').split('.')[0]);
  if (major !== Number(required)) {
    return `AppCrane tests need Node ${required} (found v${String(version).replace(/^v/, '')}): ${NODE_FIX}`;
  }
  if (loadError && /NODE_MODULE_VERSION/.test(loadError)) {
    return `better-sqlite3 in node_modules was built for a different Node than v${String(version).replace(/^v/, '')}: ` +
      `run \`npm rebuild better-sqlite3\` (or \`npm ci\`) under Node ${required}`;
  }
  return null;
}
