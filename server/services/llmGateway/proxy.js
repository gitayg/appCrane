import express from 'express';
import { pipeline } from 'stream';
import log from '../../utils/logger.js';
import {
  getConfig, getAppSettings, providerReady, providerKey, effectiveLimits, modelAllowed, mapModel,
  estimateCost, appClassification, DEFAULT_MAX_BODY_KB,
} from './config.js';
import { resolveGatewayToken } from './tokens.js';
import { recordUsage, budgetRefusal, takeRateSlot, noteGatewayProblem } from './usage.js';
import { UsageCounter, sseUsageTap } from './usageParse.js';
import { startUpstream, scrubKey, UpstreamBlocked, FORWARD_RESPONSE_HEADERS } from './upstream.js';

// The only paths the gateway forwards. Anything else under /api/service/llm
// is answered here with 404 and never reaches a provider.
export const ROUTES = Object.freeze({
  'anthropic /v1/messages': { maxField: 'max_tokens', counts: true },
  'anthropic /v1/messages/count_tokens': { maxField: null, counts: false },
  'openai /v1/chat/completions': { maxField: ['max_completion_tokens', 'max_tokens'], counts: true, streamUsage: true },
  'openai /v1/responses': { maxField: 'max_output_tokens', counts: true },
  'openai /v1/embeddings': { maxField: null, counts: true },
});

const MAX_ERROR_BODY = 64 * 1024;
const MAX_JSON_BODY = 32 * 1024 * 1024;

export function providerError(provider, status, code, message) {
  if (provider === 'anthropic') return { type: 'error', error: { type: code, message } };
  return { error: { message, type: code, code } };
}

function send(res, provider, status, code, message) {
  if (res.headersSent) return res.destroy();
  res.status(status).json(providerError(provider, status, code, message));
}

function presentedToken(req) {
  const xKey = req.headers['x-api-key'] || req.headers['api-key'];
  if (xKey) return String(xKey).trim();
  const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ''));
  return m ? m[1].trim() : '';
}

const parsers = new Map();
function jsonParser(kb) {
  if (!parsers.has(kb)) parsers.set(kb, express.json({ limit: `${kb}kb`, type: () => true }));
  return parsers.get(kb);
}

function requestedMax(body, field) {
  const fields = Array.isArray(field) ? field : [field];
  for (const f of fields) if (body[f] !== undefined && body[f] !== null) return { field: f, value: Number(body[f]) };
  return { field: fields[0], value: null };
}

/** Express handler for one allowlisted provider path. */
export function gatewayHandler(provider, path) {
  const route = ROUTES[`${provider} ${path}`];
  return (req, res) => {
    if (req.headers['via'] || req.headers['x-forwarded-host'] || req.headers['x-forwarded-for']) {
      return send(res, provider, 403, 'NOT_INTERNAL', 'This endpoint is reachable only from an app container, not the public domain.');
    }
    const who = resolveGatewayToken(presentedToken(req));
    if (!who) return send(res, provider, 401, 'authentication_error', 'Invalid or missing AppCrane LLM gateway token.');
    const { app, env } = who;
    const settings = getAppSettings(app.id);
    if (!settings.enabled) return send(res, provider, 403, 'LLM_GATEWAY_DISABLED', "The LLM gateway is turned off for this app.");
    const cfg = getConfig();
    if (!providerReady(cfg, provider)) return send(res, provider, 503, 'LLM_PROVIDER_NOT_CONFIGURED', `AppCrane has no ${provider} credential configured.`);
    const limits = effectiveLimits(cfg, settings, env);

    jsonParser(limits.max_body_kb || DEFAULT_MAX_BODY_KB)(req, res, (err) => {
      if (err) {
        const tooLarge = err.type === 'entity.too.large';
        return send(res, provider, tooLarge ? 413 : 400, tooLarge ? 'request_too_large' : 'invalid_request_error',
          tooLarge ? `Request body is over the gateway's ${limits.max_body_kb || DEFAULT_MAX_BODY_KB} KB limit.` : 'Request body must be JSON.');
      }
      forward(req, res, { provider, path, route, app, env, settings, cfg, limits });
    });
  };
}

function forward(req, res, ctx) {
  const { provider, path, route, app, env, settings, cfg, limits } = ctx;
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? { ...req.body } : null;
  if (!body) return send(res, provider, 400, 'invalid_request_error', 'Request body must be a JSON object.');
  const started = Date.now();
  const model = mapModel(cfg, provider, typeof body.model === 'string' ? body.model : null);
  const stream = body.stream === true;
  const base = { appId: app.id, env, provider, endpoint: path, model, stream };
  const refuse = (status, code, message) => {
    recordUsage({ ...base, status, outcome: 'refused', latencyMs: Date.now() - started });
    return send(res, provider, status, code, message);
  };

  if (!model) return refuse(400, 'invalid_request_error', 'model is required.');
  body.model = model;
  if (!modelAllowed(cfg, settings, provider, model, appClassification(app))) {
    return refuse(403, 'LLM_MODEL_NOT_ALLOWED', `Model ${model} is not allowed for this app through AppCrane's LLM gateway.`);
  }
  if (route.maxField && limits.max_tokens_per_request) {
    const { field, value } = requestedMax(body, route.maxField);
    if (value === null) body[field] = limits.max_tokens_per_request;
    else if (!(value <= limits.max_tokens_per_request)) {
      return refuse(400, 'LLM_MAX_TOKENS', `${field} ${value} is over this app's limit of ${limits.max_tokens_per_request} tokens per request.`);
    }
  }
  if (!takeRateSlot(app.id, env, limits.requests_per_minute)) {
    noteGatewayProblem(app, env, 'rate_limited', `LLM gateway rate limit reached for ${app.slug} (${env}): ${limits.requests_per_minute} requests per minute`);
    res.setHeader('retry-after', '60');
    return refuse(429, 'LLM_RATE_LIMITED', `This app's ${env} environment is over ${limits.requests_per_minute} LLM requests per minute.`);
  }
  const over = budgetRefusal(app.id, env, limits);
  if (over) {
    noteGatewayProblem(app, env, over.code, `LLM gateway budget reached for ${app.slug}: ${over.message}`);
    return refuse(429, over.code, over.message);
  }
  if (stream && route.streamUsage && body.stream_options?.include_usage === undefined) {
    body.stream_options = { ...(body.stream_options || {}), include_usage: true };
  }

  const key = providerKey(cfg, provider);
  const counter = new UsageCounter();
  let finished = false;
  const done = (status, outcome) => {
    if (finished) return;
    finished = true;
    const cost = route.counts ? estimateCost(cfg, model, counter.input, counter.output) : null;
    try {
      recordUsage({
        ...base, status, outcome, inputTokens: route.counts ? counter.input : 0, outputTokens: route.counts ? counter.output : 0,
        costUsd: cost, latencyMs: Date.now() - started,
      });
    } catch (e) {
      log.warn(`[llm-gateway] usage not recorded for ${app.slug}: ${e.message}`);
    }
  };

  let upReq;
  try {
    upReq = startUpstream({ cfg, provider, path, key, incomingHeaders: req.headers, body: JSON.stringify(body) });
  } catch (e) {
    if (e instanceof UpstreamBlocked) {
      done(502, 'network_error');
      noteGatewayProblem(app, env, 'upstream_blocked', `LLM gateway refused the configured ${provider} address: ${e.message}`);
      return send(res, provider, 502, 'LLM_UPSTREAM_BLOCKED', `AppCrane's ${provider} address is not allowed: ${e.message}`);
    }
    throw e;
  }

  res.on('close', () => {
    if (!res.writableFinished) {
      upReq.destroy();
      done(499, 'aborted');
    }
  });

  upReq.on('error', (e) => {
    if (finished) return;
    done(502, 'network_error');
    noteGatewayProblem(app, env, 'network_error', `LLM gateway could not reach ${provider} for ${app.slug} (${env})`);
    send(res, provider, 502, 'LLM_UPSTREAM_UNREACHABLE', `AppCrane could not reach ${provider} (${e.code || 'network error'}).`);
  });

  upReq.on('response', (up) => {
    const status = up.statusCode || 502;
    if (status >= 400) return relayError(up, res, { provider, status, key, done, app, env });
    for (const h of FORWARD_RESPONSE_HEADERS) if (up.headers[h]) res.setHeader(h, up.headers[h]);
    res.status(status);
    const isSse = String(up.headers['content-type'] || '').includes('text/event-stream');
    if (isSse) {
      res.setHeader('cache-control', 'no-cache');
      res.setHeader('x-accel-buffering', 'no');
      res.flushHeaders();
      pipeline(up, sseUsageTap(counter), res, (err) => done(status, err ? 'aborted' : 'ok'));
      return;
    }
    const chunks = [];
    let size = 0;
    up.on('data', (c) => {
      size += c.length;
      if (size <= MAX_JSON_BODY) chunks.push(c);
      if (!res.write(c)) { up.pause(); res.once('drain', () => up.resume()); }
    });
    up.on('end', () => {
      if (size <= MAX_JSON_BODY) counter.takeJsonText(Buffer.concat(chunks).toString('utf8'));
      done(status, 'ok');
      res.end();
    });
    up.on('error', () => { done(status, 'aborted'); res.destroy(); });
  });
}

function relayError(up, res, { provider, status, key, done, app, env }) {
  const chunks = [];
  let size = 0;
  up.on('data', (c) => { size += c.length; if (size <= MAX_ERROR_BODY) chunks.push(c); });
  up.on('error', () => { done(status, 'upstream_error'); res.destroy(); });
  up.on('end', () => {
    done(status, 'upstream_error');
    if (status === 401 || status === 403) {
      noteGatewayProblem(app, env, 'provider_auth', `${provider} refused AppCrane's credential (HTTP ${status})`);
      return send(res, provider, 502, 'LLM_PROVIDER_AUTH', `${provider} refused AppCrane's credential. A platform admin needs to check the LLM gateway settings.`);
    }
    if (status >= 500) noteGatewayProblem(app, env, 'upstream_5xx', `${provider} answered HTTP ${status} for ${app.slug} (${env})`);
    for (const h of FORWARD_RESPONSE_HEADERS) if (up.headers[h]) res.setHeader(h, up.headers[h]);
    res.status(status).end(scrubKey(Buffer.concat(chunks).toString('utf8'), key));
  });
}
