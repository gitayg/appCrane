-- Per-app skill assignment. Before this, prepareSkillsMount() loaded every
-- enabled skill into every container — there was no way to scope a skill
-- to specific apps. Now: a skill must be explicitly assigned to an app
-- (via this join table) for it to land in that app's Builder / Improve /
-- Ask container. The skills.enabled flag is now a global on/off switch
-- ("available for assignment") rather than a load directive.
CREATE TABLE IF NOT EXISTS app_skills (
  app_slug   TEXT NOT NULL,
  skill_slug TEXT NOT NULL,
  PRIMARY KEY (app_slug, skill_slug),
  FOREIGN KEY (app_slug)   REFERENCES apps(slug)   ON DELETE CASCADE,
  FOREIGN KEY (skill_slug) REFERENCES skills(slug) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_skills_skill ON app_skills(skill_slug);

-- Backfill: every currently-enabled skill gets assigned to every existing
-- app. Preserves the prior global behavior so no operator's running
-- agents lose their skill set on upgrade. New apps registered after this
-- migration must opt in explicitly via the Skills tab.
INSERT OR IGNORE INTO app_skills (app_slug, skill_slug)
SELECT a.slug, s.slug
FROM apps a CROSS JOIN skills s
WHERE s.enabled = 1;
