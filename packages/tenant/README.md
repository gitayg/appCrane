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

app.get('/api/notes', (req, res) => {
  const db = tenantDb(req)   // opens this user's own db.sqlite
  db.exec('CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)')
  res.json({ notes: db.prepare('SELECT * FROM notes').all() })
})
```

## API

| Function | Returns | Notes |
|---|---|---|
| `tenantDb(req, opts?)` | open `better-sqlite3` handle | needs the peer dep |
| `tenantDbPath(req, opts?)` | `string` path to `db.sqlite` | dependency-free — use with any SQLite driver |
| `tenantDir(req, opts?)` | `string` tenant dir (created unless `create:false`) | |
| `tenantKey(req)` | `{ org, userId }` | throws if the request has no identity |
| `orgFromEmail(email)` | `string` org slug | domain, sanitised, `unknown` fallback |

`req` may be an Express request (`req.get`), a Node request (`req.headers`), or a
plain headers object. `opts`: `{ root?, create? }` — `root` defaults to
`process.env.APPCRANE_TENANT_ROOT` (`/data/tenants` in an AppCrane container).

## Security

Always build tenant paths through this helper, never from raw user input — the
`X-AppCrane-*` identity headers are platform-signed, and the org slug is
sanitised so a hostile email can't traverse out of the tenant root. Consumer
domains (e.g. `gmail.com`) share an `org` label, but isolation is per-user, so
data never mixes.
