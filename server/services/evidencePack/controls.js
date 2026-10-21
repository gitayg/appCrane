// The SOC 2 Trust Services Criteria this pack carries evidence for, how
// AppCrane implements each, and which evidence files support it. The wording
// describes what the platform does; it is not an auditor's opinion.

export const FRAMEWORK = 'AICPA SOC 2 Trust Services Criteria (2017, with 2022 revised points of focus)';

export const DISCLAIMER = 'This pack is evidence to support an audit. It is not a SOC 2 report, an attestation or a certification, '
  + 'and producing it does not mean any control is designed or operating effectively. An independent auditor decides that.';

export const CONTROLS = [
  {
    id: 'CC6.1', family: 'CC6', title: 'Logical access: identities, roles and authentication',
    implementation: 'Every person and agent is a user with one platform role (platform_admin or user) and per-app roles. '
      + 'Sign-in is by SSO (OIDC or SAML) with optional SCIM provisioning, or by password; API keys are stored as SHA-256 hashes (any value left in the legacy encrypted-key column is counted in C1/encryption.json). '
      + 'Multi-factor and session-timeout settings are exported as configured.',
    evidence: ['CC6/users-and-roles.csv', 'CC6/app-role-assignments.csv', 'CC6/authentication-settings.json'],
  },
  {
    id: 'CC6.2', family: 'CC6', title: 'Credential lifecycle: issue, expiry and revocation',
    implementation: 'Personal API keys, MCP keys and Crew agent tokens expire a fixed number of days after issue (api_key_max_age_days, default 90); '
      + 'a sweep expires them and warns owners first. Key values are never exported, only their ages and states.',
    evidence: ['CC6/api-key-policy.json', 'CC6/api-key-ages.csv'],
  },
  {
    id: 'CC6.3', family: 'CC6', title: 'Periodic access reviews',
    implementation: 'Access review campaigns, when the access review module is installed, record who reviewed which grants and the decisions taken.',
    evidence: ['CC6/access-reviews.json'],
  },
  {
    id: 'CC7.2', family: 'CC7', title: 'System monitoring: audit trail and event store',
    implementation: 'Every mutating request is written to the audit log with actor, app and action; operational events go to a shared event store, '
      + 'optionally forwarded to SIEM sinks. Free-text fields are scrubbed of credentials before export.',
    evidence: ['CC7/audit-log.csv', 'CC7/audit-chain-verification.json', 'CC7/events-summary.json', 'CC7/siem-sinks.json'],
  },
  {
    id: 'CC7.3', family: 'CC7', title: 'Incident detection: critical events and job health',
    implementation: 'Critical-severity events are the incident-relevant record. Background jobs report each run to Job Health, which alerts platform admins when a job fails or is late.',
    evidence: ['CC7/critical-events.csv', 'CC7/job-health.json'],
  },
  {
    id: 'CC7.1', family: 'CC7', title: 'Vulnerability management',
    implementation: 'Deployed apps are scanned daily for vulnerable dependencies; findings open and resolve as events and feed the release check.',
    evidence: ['CC7/dependency-scans.csv'],
  },
  {
    id: 'CC8.1', family: 'CC8', title: 'Change management: deploys and release checks',
    implementation: 'Every deploy is recorded with app, environment, version, commit, artifact digest, who started it and the outcome. '
      + 'Production releases pass a release check (intake, dependencies, secrets, access rules, SSO gate, sandbox health) when that module is installed.',
    evidence: ['CC8/deployments.csv', 'CC8/release-checks.json'],
  },
  {
    id: 'A1.2', family: 'A1', title: 'Availability: backups',
    implementation: 'A local backup of the platform database, .env and managed databases runs nightly by default; an off-site (S3-compatible) backup runs nightly when configured, optionally encrypted.',
    evidence: ['A1/backup-configuration.json', 'A1/backup-history.json'],
  },
  {
    id: 'A1.3', family: 'A1', title: 'Availability: restore testing (RPO and RTO)',
    implementation: 'Scheduled restore drills restore the newest local and off-site backups into an isolated scratch area, check integrity, row counts, decryption, repository bundles and managed database dumps, '
      + 'record backup age (RPO) and restore time (RTO), and delete the scratch area. Live data is never touched.',
    evidence: ['A1/restore-drills.csv'],
  },
  {
    id: 'C1.1', family: 'C1', title: 'Confidentiality: encryption and key management',
    implementation: 'Secrets at rest (app environment variables, SSO client secrets, managed database passwords, stored tokens) are encrypted with AES-256-GCM under the instance ENCRYPTION_KEY. '
      + 'No ENCRYPTION_KEY rotation mechanism exists today; this is stated as a gap, not hidden.',
    evidence: ['C1/encryption.json'],
  },
];

export function controlsForFile(path) {
  return CONTROLS.filter((c) => c.evidence.includes(path)).map((c) => c.id);
}
