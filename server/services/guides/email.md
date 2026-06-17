# AppCrane email service — how an app sends email

AppCrane sends email on a hosted app's behalf. It is **server-side only**,
**async**, and can only deliver to **registered platform users** — an app can
never email an arbitrary address.

## Prerequisites

1. The platform admin has configured **Settings → Mail** (Microsoft Graph
   credentials). Without it, messages queue and then dead-letter to the admin.
2. The app has been **deployed on AppCrane 2.8.3+**. Every deploy injects two
   env vars into the container — no setup, no toggle, available to every app:

   | Env var | Value |
   |---|---|
   | `APPCRANE_SERVICE_TOKEN` | the app's credential for the email API |
   | `CRANE_INTERNAL_URL` | `http://host.docker.internal:5001` — AppCrane, reachable from inside the container |

   If the app is already running, **redeploy once** so the vars are present.

## The request

`POST {CRANE_INTERNAL_URL}/api/service/email`

Headers:

- `Content-Type: application/json`
- `X-AppCrane-Service-Token: {APPCRANE_SERVICE_TOKEN}`

Body fields:

| Field | Required | Notes |
|---|---|---|
| `to` | yes | Must be a registered platform user's email |
| `subject` | yes | |
| `text` | one of text/html | Plain-text body |
| `html` | one of text/html | HTML body (used over text if both given) |
| `replyTo` | no | Reply-To address |
| `env` | no | `sandbox` (default) or `production` |
| `idempotencyKey` | no | Safe retries — the same key never double-sends |

Returns **`202 { queued: true, queue_id }`** immediately. A worker delivers it
async (5 retries with backoff; on permanent failure the platform admin is
emailed).

## Node example

```js
async function notify(toEmail, subject, body) {
  const res = await fetch(`${process.env.CRANE_INTERNAL_URL}/api/service/email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AppCrane-Service-Token": process.env.APPCRANE_SERVICE_TOKEN,
    },
    body: JSON.stringify({ to: toEmail, subject, text: body }),
  });
  if (res.status !== 202) throw new Error(`email failed (${res.status}): ${await res.text()}`);
  return res.json();
}
```

## Python example

```python
import os, requests

def notify(to_email, subject, body):
    res = requests.post(
        f"{os.environ['CRANE_INTERNAL_URL']}/api/service/email",
        headers={"X-AppCrane-Service-Token": os.environ["APPCRANE_SERVICE_TOKEN"]},
        json={"to": to_email, "subject": subject, "text": body},
    )
    res.raise_for_status()   # 202 on success
    return res.json()
```

## Emailing the logged-in user

AppCrane already injects the SSO user's email on every request as
`X-AppCrane-User-Email`. Use it as the recipient — it is guaranteed to be a
platform user:

```js
const userEmail = req.headers["x-appcrane-user-email"];
await notify(userEmail, "Your report is ready", "Open the app to download it.");
```

## Rules and guarantees

- **Server-side only.** The endpoint is reachable only from the container (via
  `host.docker.internal`), 404s on the public domain, and rejects anything that
  arrived through the proxy. The token is a server env var the browser never
  sees. Never call this from frontend code.
- **Recipients are platform users only.** A non-user address returns `400`.
- **The sender is platform-controlled.** From is fixed (the Settings → Mail
  mailbox, e.g. `aimi@opswat.com`); only the display name is configurable
  (per-app `email_from_name`, else the platform default). Apps may set
  `replyTo`.

## Errors

| Status | Meaning |
|---|---|
| `202` | Queued (success) |
| `400` | Recipient is not a platform user, or subject/body missing |
| `401` | Missing or invalid `X-AppCrane-Service-Token` |
| `403` | Request reached the endpoint via the public proxy (must be internal) |
