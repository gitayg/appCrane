/**
 * Format a stream-json tool-use event as a one-line breadcrumb the UI
 * shows during plan / coder runs ("📖 Reading foo.ts", "✏️  Editing
 * bar.ts", "▶ Bash: npm test", etc.).
 *
 * Lives in its own module because both the planner pipeline (worker.js
 * handlePlan onTool) and the coder pipeline (generator.js
 * generateCode runner.on('data')) need the same formatting — keeps
 * the breadcrumb shape consistent across phases.
 *
 * Returns null for tools we want to suppress.
 */
export function formatToolBreadcrumb(ev) {
  const name  = ev?.name || '?';
  const input = ev?.input || {};
  const trim  = (s, n = 60) => { const x = String(s ?? ''); return x.length > n ? x.slice(0, n - 1) + '…' : x; };
  const baseName = (p) => trim((p || '').split('/').pop() || p);
  switch (name) {
    case 'Read':       return `📖 Reading ${baseName(input.file_path)}`;
    case 'Glob':       return `📁 Globbing ${trim(input.pattern, 50)}`;
    case 'Grep':       return `🔍 Grepping ${trim(input.pattern, 50)}${input.path ? ' in ' + baseName(input.path) : ''}`;
    case 'Bash':       return `▶ Bash: ${trim(input.command, 60)}`;
    case 'WebFetch':   return `🌐 Fetching ${trim(input.url, 60)}`;
    case 'WebSearch':  return `🔎 Searching: ${trim(input.query, 50)}`;
    case 'Edit':       return `✏️  Editing ${baseName(input.file_path)}`;
    case 'Write':      return `📝 Writing ${baseName(input.file_path)}`;
    case 'NotebookEdit': return `✏️  Editing notebook ${baseName(input.notebook_path)}`;
    case 'TodoWrite':  return `✅ Updating todo list (${(input.todos || []).length} items)`;
    case 'Task':       return `🤝 Spawning agent: ${trim(input.description, 50)}`;
    default:           return `🔧 ${name}`;
  }
}
