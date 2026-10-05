# appcrane-tenant

Cooperative per-tenant SQLite helper for apps hosted on [AppCrane](https://github.com/gitayg/appCrane).

Set `"multitenant": true` in your `deployhub.json` and AppCrane gives each of
your app's users an isolated database on the persistent `/data` volume. This
helper derives that database's path from the signed identity headers AppCrane
already sends with every request — so you never build tenant paths by hand, and
tenants can't reach each other's data.

A tenant is **(org, user)**, where `org` is the user's email domain. Files live
at `/data/tenants/<org>/u<userId>/db.sqlite`. When a user's access is revoked,
AppCrane purges their dir automatically.

## Install

Not published to npm yet. Until then, copy `index.js` into your repo, or depend
on it by path (`"appcrane-tenant": "file:../path/to/packages/tenant"`).
`better-sqlite3` is an **optional** peer dependency — only needed for `tenantDb()`.

## Usage

```js
import { tenantDb } from 'appcrane-tenant'

// Schema steps, in order. Append new ones; never edit or remove a shipped one.
const migrations = [
  'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)',
  'ALTER TABLE notes ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0',
]

app.get('/api/notes', (req, res) => {
  const db = tenantDb(req, { migrations })   // this user's own db.sqlite, upgraded if behind
  res.json({ notes: db.prepare('SELECT * FROM notes').all() })
})
```

### Schema migrations across thousands of files

One file per user means one schema per file, and the trap is drift: some files
upgraded, some not. Pass `migrations` and each file is upgraded **lazily**, the
first time it is opened after a deploy:

- keyed on `PRAGMA user_version`: step *i* runs only if the file has not had it;
- every pending step runs in one `IMMEDIATE` transaction, so a failing step rolls
  the whole upgrade back and the file stays on its old version (the open throws);
- two requests opening the same file at once upgrade it once (the second waits
  for the lock, then re-reads the version);
- a step may be a SQL string or a function given the open database;
- a file already ahead of the list (code rolled back) is opened unchanged.

A user who never comes back is never upgraded, which costs nothing: their file is
upgraded the day they return.

## API

| Function | Returns | Notes |
|---|---|---|
| `tenantDb(req, opts?)` | open `better-sqlite3` handle | needs the peer dep |
| `tenantDbPath(req, opts?)` | `string` path to `db.sqlite` | dependency-free — use with any SQLite driver |
| `tenantDir(req, opts?)` | `string` tenant dir (created unless `create:false`) | |
| `tenantStorageDir(req, opts?)` | `string` `<tenantDir>/storage/` | for blobs/uploads, created unless `create:false` |
| `tenantFile(req, name, opts?)` | `string` safe path in `storage/` | `name` reduced to a basename; throws on `.`/`..`/empty/NUL |
| `tenantUsage(req, opts?)` | `number` bytes used (db + storage) | walks the tenant dir |
| `tenantQuotaBytes()` | `number` | from `APPCRANE_TENANT_QUOTA_BYTES`, `0` = unlimited |
| `assertTenantQuota(req, opts?)` | — | throws `TENANT_QUOTA_EXCEEDED` if at/over quota; no-op when unlimited |
| `tenantKey(req)` | `{ org, userId }` | throws if the request has no identity |
| `orgFromEmail(email)` | `string` org slug | domain, sanitised, `unknown` fallback |

`req` may be an Express request (`req.get`), a Node request (`req.headers`), or a
plain headers object. `opts`: `{ root?, create?, migrations? }` (`migrations` is
`tenantDb` only, see above) — `root` defaults to
`process.env.APPCRANE_TENANT_ROOT` (`/data/tenants` in an AppCrane container).

### Storage + quota

Each tenant gets a `storage/` dir alongside its DB for files/uploads. Configure
an optional cap with `"tenant_quota_mb": <n>` in `deployhub.json`; AppCrane
injects it as `APPCRANE_TENANT_QUOTA_BYTES`, and `assertTenantQuota(req)` (called
before a write) throws once the tenant is full. The quota covers the DB **and**
storage, and revoke purges both.

## Security

Always build tenant paths through this helper, never from raw user input — the
`X-AppCrane-*` identity headers are platform-signed, and the org slug is
sanitised so a hostile email can't traverse out of the tenant root. Consumer
domains (e.g. `gmail.com`) share an `org` label, but isolation is per-user, so
data never mixes.
