"""Write an audit event to AppCrane (POST /api/service/audit/events).

Authenticated by this app's APPCRANE_SERVICE_TOKEN over CRANE_INTERNAL_URL,
both injected by AppCrane; the call works from the server only. The action
must be registered on the app first (app page > Audit events). Pass the
incoming request's headers to record the signed-in user as the actor: the
signed X-AppCrane-* headers are forwarded and AppCrane checks them. Without
them the actor is the app itself.

    audit_event("invoice.paid", headers=request.headers, targets=[{"type": "invoice", "id": inv_id}])
"""

from __future__ import annotations

import json
import os
import urllib.request


def audit_event(action, *, headers=None, targets=None, metadata=None, actor=None, occurred_at=None, idempotency_key=None):
    base = os.environ.get("CRANE_INTERNAL_URL")
    token = os.environ.get("APPCRANE_SERVICE_TOKEN")
    if not base or not token:
        raise RuntimeError("audit: CRANE_INTERNAL_URL / APPCRANE_SERVICE_TOKEN are not set (not running on AppCrane)")
    identity = {k.lower(): v for k, v in (headers or {}).items() if k.lower().startswith("x-appcrane-")}
    body = {"action": action, "targets": targets, "metadata": metadata, "actor": actor,
            "occurred_at": occurred_at, "idempotency_key": idempotency_key}
    if identity:
        body["identity"] = identity
    body = {k: v for k, v in body.items() if v is not None}
    req = urllib.request.Request(
        base.rstrip("/") + "/api/service/audit/events",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", "x-appcrane-service-token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read())["event"]
