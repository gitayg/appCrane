// appcrane_adopt_app: the MCP face of services/adopt/flow.js. Registered in
// mcpTools.js's TOOLS array. env values travel as [{ key, value }] so the MCP
// audit redaction (utils/auditRedact.js masks any `value` field) keeps every
// one of them out of audit_log; a { KEY: value } map would be logged verbatim
// for any key whose name does not look like a secret.

const MAX_ENV_ITEMS = 200;

function envArrayToMap(list) {
  if (list == null) return {};
  if (!Array.isArray(list)) throw new Error('env_vars must be an array of { key, value }');
  if (list.length > MAX_ENV_ITEMS) throw new Error(`env_vars may hold at most ${MAX_ENV_ITEMS} entries`);
  const out = {};
  for (const e of list) {
    if (!e || typeof e.key !== 'string' || typeof e.value !== 'string') throw new Error('each env_vars entry needs { key: string, value: string }');
    if (Object.prototype.hasOwnProperty.call(out, e.key)) throw new Error(`env var ${e.key} is listed twice`);
    out[e.key] = e.value;
  }
  return out;
}

function compactReport(r) {
  return {
    verdict: r.verdict,
    project: r.project,
    works: r.works.map((i) => `${i.title}: ${i.detail}`),
    changes: r.changes.map((i) => ({ level: i.level, title: i.title, detail: i.detail, blocking: i.blocking, opens_request: i.request })),
    risks: r.risks.map((i) => ({ severity: i.severity, title: i.title, detail: i.detail, preview: i.preview })),
    risk_counts: r.risk_counts,
    env_to_fill: r.env.map((v) => ({ key: v.key, scope: v.scope, build_time: v.build_time, value_found_in_upload: v.value_in_upload, hint: v.hint })),
    supabase_edge_env: r.supabase_edge_env,
    files_added: r.scaffold,
    skipped: r.skipped,
  };
}

export const adoptAppTool = {
  name: 'appcrane_adopt_app',
  description:
    'Adopt an app built with Lovable, Bolt, v0, Replit, Figma Make or any GitHub repo / zip onto this AppCrane: behind its SSO, scanned, deployed to the SANDBOX only. ' +
    'Two steps. (1) action="analyze" with github_url (public, or private with github_token) or zip_url (an https link to a zip). Nothing from the project is executed: AppCrane reads the files, detects the framework, build/start commands and port, the env vars the code reads, Supabase/Firebase/Clerk/Auth0 usage and hardcoded secrets, and returns an adoption report plus an adoption_id. A Lovable/Bolt/v0/Replit project URL is not importable directly; the error says which export step to use. ' +
    '(2) action="adopt" with adoption_id, name, slug and env_vars=[{key,value}] creates a Crane-hosted managed app, commits the code plus any missing Dockerfile/deployhub.json/health endpoint, stores the env vars encrypted for the sandbox, starts the first sandbox deploy, records the intake (purpose, data_classification, intake_answers) and with open_requests=true opens one request per needed change for the coder. ' +
    'stage must be "sandbox"; production is refused. A report with critical risks (e.g. a Supabase service-role key in client code) needs acknowledge_risks=true. Follow the deploy with appcrane_wait_deploy.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['analyze', 'adopt'], description: 'analyze a source, or adopt a previous analysis.' },
      github_url: { type: 'string', description: 'analyze: GitHub repository URL (optionally .../tree/<branch>).' },
      ref: { type: 'string', description: 'analyze: branch, tag or commit. Defaults to the default branch.' },
      github_token: { type: 'string', description: 'analyze: a token that can read a private repository. Used once, never stored.' },
      zip_url: { type: 'string', description: 'analyze: https URL of a project zip (private addresses and redirects are refused).' },
      adoption_id: { type: 'string', description: 'adopt: the id returned by analyze.' },
      name: { type: 'string', description: 'adopt: display name.' },
      slug: { type: 'string', description: 'adopt: URL slug, lowercase letters, digits and dashes.' },
      description: { type: 'string', description: 'adopt: optional app description.' },
      env_vars: {
        type: 'array', maxItems: MAX_ENV_ITEMS,
        items: { type: 'object', properties: { key: { type: 'string' }, value: { type: 'string' } }, required: ['key', 'value'], additionalProperties: false },
        description: 'adopt: sandbox env vars to set (stored encrypted). Values found in an uploaded .env are used for keys you leave out.',
      },
      intake: {
        type: 'object',
        properties: {
          purpose: { type: 'string' },
          data_classification: { type: 'string' },
          owner: { type: 'number' },
          intake_answers: {
            type: 'object',
            properties: { personal_data: { type: 'boolean' }, external_integrations: { type: 'string' }, access: { type: 'string' } },
            additionalProperties: false,
          },
        },
        additionalProperties: false,
        description: 'adopt: intake record for the new app.',
      },
      open_requests: { type: 'boolean', description: 'adopt: open a request per change the report asks for.' },
      acknowledge_risks: { type: 'boolean', description: 'adopt: required when the report has critical risks.' },
      stage: { type: 'string', enum: ['sandbox'], description: 'adopt: must be "sandbox". Production is refused.' },
    },
    required: ['action'],
    additionalProperties: false,
  },
  requiredRole: 'create_app',
  handler: async (user, args) => {
    const flow = await import('./flow.js');
    if (args.action === 'analyze') {
      let source;
      if (args.github_url && args.zip_url) throw new Error('Give github_url or zip_url, not both.');
      if (args.github_url) {
        source = { kind: 'github', url: args.github_url, ref: args.ref, github_token: args.github_token };
      } else if (args.zip_url) {
        flow.assertMayAdopt(user);
        const { toolGuideFor } = await import('./sources.js');
        const guide = toolGuideFor(args.zip_url);
        if (guide) throw new Error(`${guide.label} project links cannot be imported directly. ${guide.steps}`);
        const { fetchToBuffer } = await import('../remoteFetch.js');
        const buffer = await fetchToBuffer(args.zip_url);
        source = { kind: 'zip', buffer, filename: new URL(args.zip_url).pathname.split('/').pop() || 'download.zip' };
      } else {
        throw new Error('analyze needs github_url or zip_url.');
      }
      const out = await flow.analyzeSource(user, source);
      return {
        adoption_id: out.id, source: out.source, suggested: out.suggested, report: compactReport(out.report),
        next: `Ask the user for the env values in report.env_to_fill, then call appcrane_adopt_app action="adopt" adoption_id="${out.id}" name=... slug=... env_vars=[...] stage="sandbox".`,
      };
    }
    if (args.action === 'adopt') {
      if (args.env != null && args.env !== 'sandbox') throw new Error('Adoption deploys to the sandbox only; production is refused.');
      const result = await flow.adoptAnalyzed(user, {
        id: args.adoption_id, name: args.name, slug: args.slug, description: args.description,
        stage: args.stage ?? 'sandbox', env_vars: envArrayToMap(args.env_vars), intake: args.intake,
        open_requests: args.open_requests === true, acknowledge_risks: args.acknowledge_risks === true,
      });
      const d = result.deployments[0];
      return {
        ...result,
        next: d ? `Sandbox deploy started (deployment ${d.deployment_id}). Follow it with appcrane_wait_deploy deployment_id=${d.deployment_id}.` : 'No deploy started; run appcrane_deploy slug=... stage="sandbox".',
      };
    }
    throw new Error('action must be "analyze" or "adopt".');
  },
};
