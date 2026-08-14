/**
 * Shared DB seed for the v2.44.0 Caddy-edge tests.
 *
 * Lives in fixtures because two things must agree on it byte-for-byte: the
 * snapshot in caddyfile.pre-edge-hardening.txt (generated once from the
 * v2.43.1 generator) and test/edge-hardening.test.js, which regenerates
 * against the CURRENT generator and diffs the two. If the seed drifts, the
 * diff stops meaning "what the change did".
 *
 * Slots are hard-coded rather than allocated: getPortsForSlot(slot) is what
 * ends up in the Caddyfile text, so the snapshot is only stable if the slots
 * are.
 */
export function seedApps(db) {
  const insert = db.prepare(
    `INSERT INTO apps (name, slug, slot, source_type, auth_mode, auth_bypass_paths,
                       domain, frame_ancestors, slug_aliases, visibility)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  );
  const deploy = db.prepare(
    'INSERT INTO deployments (app_id, env, status) VALUES (?,?,?)'
  );
  const ids = {};
  const mk = (slug, slot, o = {}) => {
    const id = insert.run(
      slug, slug, slot, 'managed',
      o.auth_mode ?? 'authenticated',
      o.auth_bypass_paths ?? null,
      o.domain ?? null,
      o.frame_ancestors ?? null,
      o.slug_aliases ?? null,
      'private'
    ).lastInsertRowid;
    for (const env of o.envs ?? ['production', 'sandbox']) deploy.run(id, env, 'live');
    ids[slug] = id;
    return id;
  };

  // The six app shapes the generated Caddyfile has to cover, plus the two
  // no-route shapes that prove the change stays out of them.
  mk('plain', 1);                                                        // 1. nothing set
  mk('headless', 2, { auth_mode: 'headless', envs: ['production'] });    // 2. no forward_auth
  mk('bypasser', 3, { auth_bypass_paths: '["/ws/runner"]' });            // 3. per-path exemption
  mk('custom', 4, { domain: 'custom.test.local', envs: ['production'] });// 4. own hostname
  mk('framed', 5, { frame_ancestors: 'https://portal.example.com' });    // 5. union (unchanged)
  mk('denied', 6, { frame_ancestors: "'none'" });                        // 6. opt-out sentinel
  mk('narrow', 7, { frame_ancestors: "'none' https://portal.example.com" });
  mk('aliased', 8, { slug_aliases: '["oldname"]', envs: ['production'] });
  mk('undeployed', 9, { envs: [] });

  db.prepare('INSERT INTO app_domain_aliases (app_id, domain) VALUES (?,?)')
    .run(ids.custom, 'old.test.local');

  return ids;
}
