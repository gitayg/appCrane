# Multitenant Notes — AppCrane example

A tiny app showing per-tenant isolation with [`appcrane-tenant`](../../packages/tenant).
Every `(org, user)` gets their own SQLite notes DB; the app never touches another
tenant's data and never constructs a tenant path itself.

## How it works

1. `deployhub.json` sets `"multitenant": true`. AppCrane then injects
   `APPCRANE_TENANT_ROOT=/data/tenants` and purges a tenant's dir when their
   access is revoked.
2. Each request already carries AppCrane's signed identity headers
   (`X-AppCrane-User-Email`, `X-AppCrane-User-Id`).
3. `tenantDb(req)` derives `/data/tenants/<org>/u<userId>/db.sqlite` from those
   headers and opens it. That's the whole integration — see [server.js](server.js).

## Run locally

```bash
npm install
# Simulate what AppCrane injects at runtime:
APPCRANE_TENANT_ROOT=./data/tenants PORT=3000 npm start

# Acme user adds a note:
curl -X POST localhost:3000/api/notes -H 'content-type: application/json' \
  -H 'X-AppCrane-User-Email: alice@acme.com' -H 'X-AppCrane-User-Id: 1' \
  -d '{"body":"first note"}'

# A different org sees an empty list — separate DB file:
curl localhost:3000/api/notes \
  -H 'X-AppCrane-User-Email: bob@globex.com' -H 'X-AppCrane-User-Id: 2'
```

## Per-tenant storage + quota

`deployhub.json` also sets `"tenant_quota_mb": 50`, so AppCrane injects
`APPCRANE_TENANT_QUOTA_BYTES`. The file endpoints show it in action:

```bash
# store a file in the caller's own storage dir:
curl -X PUT localhost:3000/api/files/profile.json -H 'content-type: application/json' \
  -H 'X-AppCrane-User-Email: alice@acme.com' -H 'X-AppCrane-User-Id: 1' \
  -d '{"theme":"dark"}'
# -> 413 with {"error":"...quota exceeded..."} once the tenant is over 50 MB
```

`tenantFile(req, name)` reduces `name` to a safe basename (no traversal), and
`assertTenantQuota(req)` throws `TENANT_QUOTA_EXCEEDED` before the write when the
tenant is full. Both the DB and `storage/` live under the same tenant dir, so
the quota covers everything and revoke purges it all.

## Using it in your own app

`appcrane-tenant` isn't on npm yet — until it is, either copy
[`packages/tenant/index.js`](../../packages/tenant/index.js) into your repo, or
depend on it by path as this example does (`"appcrane-tenant": "file:..."`).
`tenantDbPath(req)` returns just the path if you use a different SQLite driver.
