import http from 'http';
import { randomUUID } from 'crypto';
import { mkdtempSync, mkdirSync, readdirSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// A local Secrets Manager speaking the JSON protocol, with stage labels moving
// as the API docs say. Not a test file: helpers for test/secrets-provider*.test.js.

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export const K_A = 'a1'.repeat(32);
export const K_B = 'b2'.repeat(32);

const err = (type, message) => Object.assign(new Error(message), { type });

export function fakeSecretsManager() {
  const secrets = new Map();
  const calls = [];
  const faults = {}; // op -> (input) => error to throw, { reply } to answer 200 with, or undefined

  const need = (id) => {
    const s = secrets.get(id) || [...secrets.values()].find((x) => x.arn === id);
    if (!s) throw err('ResourceNotFoundException', "Secrets Manager can't find the specified secret.");
    return s;
  };
  const withStage = (s, stage) => [...s.versions.entries()].find(([, v]) => v.stages.has(stage));
  const moveCurrent = (s, id) => {
    const old = withStage(s, 'AWSCURRENT');
    if (old && old[0] === id) return;
    const prev = withStage(s, 'AWSPREVIOUS');
    if (prev) prev[1].stages.delete('AWSPREVIOUS');
    if (old) { old[1].stages.delete('AWSCURRENT'); old[1].stages.add('AWSPREVIOUS'); }
    s.versions.get(id).stages.add('AWSCURRENT');
  };
  const ops = {
    GetSecretValue({ SecretId, VersionStage }) {
      const s = need(SecretId);
      const hit = withStage(s, VersionStage || 'AWSCURRENT');
      if (!hit) throw err('ResourceNotFoundException', 'no version with that stage');
      return { ARN: s.arn, Name: s.name, VersionId: hit[0], SecretString: hit[1].text, VersionStages: [...hit[1].stages] };
    },
    DescribeSecret({ SecretId }) {
      const s = need(SecretId);
      return { ARN: s.arn, Name: s.name, VersionIdsToStages: Object.fromEntries([...s.versions].map(([id, v]) => [id, [...v.stages]])) };
    },
    CreateSecret({ Name, SecretString, ClientRequestToken }) {
      if (secrets.has(Name)) throw err('ResourceExistsException', 'exists');
      const id = ClientRequestToken || randomUUID();
      const s = { name: Name, arn: `arn:aws:secretsmanager:us-east-1:111122223333:secret:${Name}-AbCdEf`, versions: new Map([[id, { text: SecretString, stages: new Set(['AWSCURRENT']) }]]) };
      secrets.set(Name, s);
      return { ARN: s.arn, Name, VersionId: id };
    },
    PutSecretValue({ SecretId, SecretString, ClientRequestToken, VersionStages }) {
      const s = need(SecretId);
      const id = ClientRequestToken || randomUUID();
      s.versions.set(id, { text: SecretString, stages: new Set() });
      if (VersionStages) {
        for (const stage of VersionStages) {
          const old = withStage(s, stage);
          if (old) old[1].stages.delete(stage);
          s.versions.get(id).stages.add(stage);
        }
      } else {
        moveCurrent(s, id);
      }
      return { ARN: s.arn, Name: s.name, VersionId: id, VersionStages: [...s.versions.get(id).stages] };
    },
    UpdateSecretVersionStage({ SecretId, VersionStage, MoveToVersionId, RemoveFromVersionId }) {
      const s = need(SecretId);
      const holder = withStage(s, VersionStage);
      if (holder && MoveToVersionId && holder[0] !== RemoveFromVersionId && holder[0] !== MoveToVersionId) throw err('InvalidParameterException', 'the stage is on another version');
      if (MoveToVersionId && VersionStage === 'AWSCURRENT') moveCurrent(s, MoveToVersionId);
      else {
        if (RemoveFromVersionId) s.versions.get(RemoveFromVersionId)?.stages.delete(VersionStage);
        if (MoveToVersionId) s.versions.get(MoveToVersionId).stages.add(VersionStage);
      }
      return { ARN: s.arn, Name: s.name };
    },
  };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const op = String(req.headers['x-amz-target'] || '').split('.')[1];
      const input = body ? JSON.parse(body) : {};
      calls.push({ op, input });
      const reply = (status, obj) => {
        res.writeHead(status, { 'Content-Type': 'application/x-amz-json-1.1' });
        res.end(JSON.stringify(obj));
      };
      try {
        const injected = faults[op]?.(input);
        if (injected?.reply) return reply(200, injected.reply);
        if (injected) throw injected;
        reply(200, ops[op](input));
      } catch (e) {
        reply(e.status || 400, { __type: e.type || 'InternalServiceError', message: e.message });
      }
    });
  });

  return {
    secrets, calls, faults, err,
    seed(name, text) { return ops.CreateSecret({ Name: name, SecretString: text }); },
    current(name) { return ops.GetSecretValue({ SecretId: name }).SecretString; },
    stages(name) { return ops.DescribeSecret({ SecretId: name }).VersionIdsToStages; },
    writes() { return calls.filter((c) => /Put|Create|Update/.test(c.op)); },
    async start() {
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      this.url = `http://127.0.0.1:${server.address().port}`;
      return this;
    },
    stop() { server.closeAllConnections(); server.close(); },
    awsEnv() {
      return {
        AWS_ENDPOINT_URL_SECRETS_MANAGER: this.url,
        AWS_ACCESS_KEY_ID: 'AKIAFAKEFORTESTS', AWS_SECRET_ACCESS_KEY: 'fake-secret-for-tests', AWS_REGION: 'us-east-1',
        AWS_EC2_METADATA_DISABLED: 'true', AWS_MAX_ATTEMPTS: '1',
      };
    },
  };
}

/**
 * A directory that looks like an AppCrane checkout with its own .env. Code that
 * finds .env next to itself (server/index.js, configBackup) runs here under
 * SANDBOX_NODE_FLAGS and never sees the real repo's .env.
 */
export function sandboxTree() {
  const dir = mkdtempSync(join(tmpdir(), 'crane-secrets-'));
  for (const name of readdirSync(ROOT)) {
    if (!['.env', 'data', '.git', '.claude', 'test'].includes(name)) symlinkSync(join(ROOT, name), join(dir, name));
  }
  mkdirSync(join(dir, 'data'));
  return dir;
}
export const SANDBOX_NODE_FLAGS = ['--preserve-symlinks', '--preserve-symlinks-main'];

export function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith('AWS_') || k.startsWith('APPCRANE_SECRETS_') || ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY', 'NODE_TEST_CONTEXT'].includes(k)) delete env[k];
  }
  return { ...env, LOG_LEVEL: 'info', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1', APPCRANE_CHECKIN: 'off', ...extra };
}
