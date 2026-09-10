import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import {
  validateVolumePaths,
  resolveVolumeMounts,
  MAX_VOLUME_PATHS,
  DEFAULT_CONTAINER_PATH,
} from '../server/services/containerRuntimeSpec.js';

// The catalogue's `volume_paths`, and the measurement it is derived from.
//
// WHAT THE FIELD IS. v2.70.0 gave an app row `volume_paths` — the container
// paths it persists, each bind-mounted from <shared>/volumes/<path> so a
// redeploy's `docker rm -f` (services/docker.js stopApp) stops throwing them
// away with the writable layer. The catalogue is where that fact belongs for a
// pulled image: the operator installing BookStack has no way to know it writes
// /config, and every entry that got this wrong lost its data silently.
//
// WHY THE NAME IS `volume_paths` AND NOT `volumes`. The value is copied
// verbatim into the `volume_paths` field of POST/PUT /api/apps and thence into
// the apps.volume_paths column, and validated by the same validateVolumePaths()
// at both ends — one name at every hop, no mapping table to get wrong. It is
// deliberately NOT `volumes`, because in every Compose file in existence
// `volumes:` is a list of `host:container` pairs, and a colon is precisely what
// validateVolumePaths refuses. A name that invites the wrong shape is the wrong
// name.
//
// WHERE THE NUMBERS COME FROM. Each entry's paths were read from that image's
// OWN config blob, fetched from its registry on 2026-09-09 — the `Volumes` map
// of the linux/amd64 image config, addressed by the digest recorded beside it
// below. NOT from upstream compose files, not from documentation, not from
// reasoning about what an app "probably" writes. 64 of the 67 entries name an
// image; all 64 configs were read; 26 declare a VOLUME and 23 declare at least
// one that is not /data. Those 23 are the whole of MEASURED.
//
// THIS TEST IS NETWORK-FREE, like test/app-catalog-data.test.js beside it.
// The registry answer is baked in below rather than re-fetched, because Docker
// Hub rate-limits anonymous callers at 100 manifest requests an hour and a
// suite that spends that budget is a suite that goes red for reasons that have
// nothing to do with the change under test. Re-measuring is a deliberate act,
// not something CI does by accident.
//
// SHIPS_CONTENT IS THE OTHER HALF, and it is the half that decides whether a
// declaration is safe today. A BIND mount does not inherit the image's content
// — measured on the build host: an empty host directory bound over an image
// path that held one file yields zero files, while a NAMED volume over the same
// path yields one, because Docker seeds only the latter. So declaring a path
// the image SEEDS replaces that content with an empty directory on first boot.
// Every path below was checked by streaming the image's own layer tars from the
// registry and listing the entries under it; the ones that turned out to hold
// files or subdirectories are recorded in SHIPS_CONTENT, which is the handoff
// list for seed-on-first-use. The other 30 paths are an empty directory, or
// absent entirely, in the image — for those a bind mount is already exactly
// what Docker would have produced.

const MEASURED = {
  'apache-ofbiz': {
    image: 'ghcr.io/apache/ofbiz',
    config: 'sha256:66b5b92dc23eb18e7df8d11855e3d6040c4ab91e707227ab0bca2c37ff4cca2a',
    paths: ['/docker-entrypoint-hooks', '/ofbiz/config', '/ofbiz/lib-extra', '/ofbiz/runtime'],
  },
  'appsmith': {
    image: 'appsmith/appsmith-ce',
    config: 'sha256:ea65063a9e219066103dec67098f0cd6dbb48c91dc36f364af70ba2ba28c6d0d',
    paths: ['/appsmith-stacks'],
  },
  'bookstack': {
    image: 'linuxserver/bookstack',
    config: 'sha256:18b3be002b116072bc479d37068b533524eea5c805ddf7fbb715cb60279ba239',
    paths: ['/config'],
  },
  'docmost': {
    image: 'docmost/docmost',
    config: 'sha256:0f146d72f36fa6ff9b12147b72719ca80df208342ecd1b757dd43f93b8a332e9',
    paths: ['/app/data/storage'],
  },
  'dolibarr': {
    image: 'dolibarr/dolibarr',
    config: 'sha256:63d0be7f813e1a58de5243f141e919536a16f92d6880a36c2df5c3c3c2ff20ea',
    paths: ['/var/www/documents', '/var/www/html/custom'],
  },
  'erpnext': {
    image: 'frappe/erpnext',
    config: 'sha256:4414072c4b13a44e9ecb1444d616a5d8988998665ac0acfe322d0cddbe8af167',
    paths: ['/home/frappe/frappe-bench/logs', '/home/frappe/frappe-bench/sites'],
  },
  'focalboard': {
    image: 'mattermost/focalboard',
    config: 'sha256:58f6f9f2684a6f8780857909db2a4d96093f792ad8b612722d3b6f7ca2512f50',
    paths: ['/opt/focalboard/data'],
  },
  'formbricks': {
    image: 'formbricks/formbricks',
    config: 'sha256:517c82fc57cf19fdca6206e53010bbfd7c3429a03d8b41e58324271607e171e8',
    paths: ['/home/nextjs/apps/web/saml-connection', '/home/nextjs/apps/web/uploads'],
  },
  'frappe-hr': {
    image: 'frappe/erpnext',
    config: 'sha256:4414072c4b13a44e9ecb1444d616a5d8988998665ac0acfe322d0cddbe8af167',
    paths: ['/home/frappe/frappe-bench/logs', '/home/frappe/frappe-bench/sites'],
  },
  'kanboard': {
    image: 'kanboard/kanboard',
    config: 'sha256:93a553bd589ea2bda9175a8e3ed113c3f6857dd6f5530abaa861fe8e1c7197ff',
    paths: ['/etc/nginx/ssl', '/var/www/app/data', '/var/www/app/plugins'],
  },
  'mattermost': {
    image: 'mattermost/mattermost-team-edition',
    config: 'sha256:d492cf4f01c425bb26ef3aec2acaab3cc7989f1253f9d3f419eb33117908b3c1',
    paths: ['/mattermost/client/plugins', '/mattermost/config', '/mattermost/data', '/mattermost/logs', '/mattermost/plugins'],
  },
  'mautic': {
    image: 'mautic/mautic',
    config: 'sha256:cd11fab2d1c42c3bec4c27d7eb6f0595b7ff96cab86efea9085f8662ff0bf91e',
    paths: ['/var/www/html/config', '/var/www/html/docroot/media/files', '/var/www/html/docroot/media/images', '/var/www/html/var/logs'],
  },
  'mayan-edms': {
    image: 'mayanedms/mayanedms',
    config: 'sha256:39cea7a55071edf0086c12ac3ba65b43c5e76518cbb350729a24feb20d4ef5c5',
    paths: ['/var/lib/mayan'],
  },
  'odoo': {
    image: 'odoo',
    config: 'sha256:138d2c15ffd0fe00d44ea2db52b585f1702fba67bfced174dba6e0857a680e98',
    paths: ['/mnt/extra-addons', '/var/lib/odoo'],
  },
  'openproject': {
    image: 'openproject/openproject:17',
    config: 'sha256:5581eee79378060b18bf584e33020825b01142dfa96c4df8c31712aadf13a9ba',
    paths: ['/var/openproject/assets', '/var/openproject/pgdata'],
  },
  'orangehrm': {
    image: 'orangehrm/orangehrm',
    config: 'sha256:27fc27c550cdfc06f84111ce2f60e5bfa77d66cb33185e03791516d749f609a6',
    paths: ['/var/www/html'],
  },
  'outline': {
    image: 'outlinewiki/outline',
    config: 'sha256:ab2c5a0052ebcd7560ed02fff9e3bae4dbbbe28c14aa7a15bbada055fbb75430',
    paths: ['/var/lib/outline/data'],
  },
  'paperless-ngx': {
    image: 'paperlessngx/paperless-ngx',
    config: 'sha256:04be29c9a534e0f83c9df8131eb48990a2527e47b997ab4ba40ce0d9bce770e5',
    paths: ['/usr/src/paperless/consume', '/usr/src/paperless/data', '/usr/src/paperless/export', '/usr/src/paperless/media'],
  },
  'rocketchat': {
    image: 'rocket.chat',
    config: 'sha256:19da568b3b43aacd8175096be07aa1fde207d57d9e55ddb38571f07757e888f9',
    paths: ['/app/uploads'],
  },
  'simplerisk': {
    image: 'simplerisk/simplerisk',
    config: 'sha256:3cbf9058df022498bdca937bd5f2570bd63f12862fdd22ba64100479476f300a',
    paths: ['/configurations', '/etc/apache2/ssl', '/passwords', '/var/lib/mysql', '/var/log', '/var/www/simplerisk'],
  },
  'snipe-it': {
    image: 'snipe/snipe-it',
    config: 'sha256:63548525131a25bcae912aa8416e33e1c8951a22ab76011c6d779d0ca327e340',
    paths: ['/var/lib/snipeit'],
  },
  'tryton': {
    image: 'tryton/tryton',
    config: 'sha256:3ab0abe768c8bb3056f2b1265ded9b232ace65a3ac0e6e38a9ab00571b75b091',
    paths: ['/var/lib/trytond/db'],
  },
  'wikijs': {
    image: 'requarks/wiki',
    config: 'sha256:dee4dfdac3e10a59c1254809d1bc824bfed290ee8818bf9f6fbdeb2a82c6cfa2',
    paths: ['/wiki/data/content'],
  },
};

const SHIPS_CONTENT = {
  'apache-ofbiz': ['/docker-entrypoint-hooks'],
  'dolibarr': ['/var/www/html/custom'],
  'erpnext': ['/home/frappe/frappe-bench/logs', '/home/frappe/frappe-bench/sites'],
  'focalboard': ['/opt/focalboard/data'],
  'frappe-hr': ['/home/frappe/frappe-bench/logs', '/home/frappe/frappe-bench/sites'],
  'mattermost': ['/mattermost/config'],
  'mautic': ['/var/www/html/config', '/var/www/html/docroot/media/files', '/var/www/html/docroot/media/images'],
  'orangehrm': ['/var/www/html'],
  'paperless-ngx': ['/usr/src/paperless/data'],
  'simplerisk': ['/etc/apache2/ssl', '/passwords', '/var/lib/mysql', '/var/log', '/var/www/simplerisk'],
  'snipe-it': ['/var/lib/snipeit'],
};

const DECLARES_ONLY_DATA = ['budibase', 'senaite', 'zulip'];

const CATALOG = JSON.parse(
  readFileSync(new URL('../server/services/appCatalog.json', import.meta.url), 'utf8'),
);
const bySlug = new Map(CATALOG.map(e => [e.slug, e]));

test('every declared set matches the image config it was read from', () => {
  // Both directions. Dropping a path loses that app's state again; adding one
  // that no image config named is the failure this whole file exists to stop —
  // a plausible-looking path nobody measured. Re-measuring an image is what
  // moves this fixture, not an edit to the catalogue.
  for (const [slug, m] of Object.entries(MEASURED)) {
    const entry = bySlug.get(slug);
    assert.ok(entry, `catalogue lost the '${slug}' entry that MEASURED covers`);
    assert.equal(entry.image, m.image,
      `${slug}: the image changed, so ${m.config} is no longer the config these paths came from — re-measure`);
    assert.deepEqual(entry.volume_paths, m.paths,
      `${slug}: volume_paths does not match the VOLUME set read from ${m.config}`);
  }
  const declared = CATALOG.filter(e => e.volume_paths !== undefined).map(e => e.slug).sort();
  assert.deepEqual(declared, Object.keys(MEASURED).sort(),
    'an entry carries volume_paths that no image measurement backs (or lost the field)');
});

test('an image whose only VOLUME is /data declares nothing', () => {
  // /data is mounted for every app, declared or not. resolveVolumeMounts skips
  // a declared path already covered by another mount, so declaring /data would
  // be a field that reads as configuration and does exactly nothing.
  for (const slug of DECLARES_ONLY_DATA) {
    const entry = bySlug.get(slug);
    assert.ok(entry, `catalogue lost the '${slug}' entry`);
    assert.equal(entry.volume_paths, undefined,
      `${slug}: its image declares only /data, which is already mounted — the field must be absent`);
  }
});

test('every declared path survives the write-boundary validator unchanged', () => {
  // The catalogue value goes to PUT /api/apps, which runs it through exactly
  // this function. A value that only survives after normalisation is a value
  // whose stored form differs from its catalogue form, and then two records of
  // the same fact disagree.
  for (const e of CATALOG) {
    if (e.volume_paths === undefined) continue;
    assert.ok(Array.isArray(e.volume_paths), `${e.slug}: volume_paths must be an array`);
    assert.ok(e.volume_paths.length > 0,
      `${e.slug}: an empty array is not "no volumes" — omit the field`);
    assert.ok(e.volume_paths.length <= MAX_VOLUME_PATHS, `${e.slug}: over the ${MAX_VOLUME_PATHS} path cap`);
    assert.deepEqual(validateVolumePaths(e.volume_paths), e.volume_paths,
      `${e.slug}: volume_paths is not already in the validator's normal form`);
  }
});

test('a declared path is never one the app already gets, or one covered by a sibling', () => {
  // resolveVolumeMounts reports both cases as `skipped` rather than mounting
  // them. A skipped path in the catalogue is a promise of persistence the
  // deployer does not keep, so the catalogue must never contain one.
  for (const e of CATALOG) {
    if (e.volume_paths === undefined) continue;
    const { mounts, skipped } = resolveVolumeMounts({ sharedDir: '/srv/app/shared', paths: e.volume_paths });
    assert.deepEqual(skipped, [],
      `${e.slug}: ${JSON.stringify(skipped)} would be skipped, not mounted`);
    assert.equal(mounts.length, e.volume_paths.length + 1,
      `${e.slug}: expected one mount per declared path plus ${DEFAULT_CONTAINER_PATH}`);
    assert.equal(mounts[0].container, DEFAULT_CONTAINER_PATH, `${e.slug}: /data must still be mount 0`);
  }
});

test('only an image-backed entry declares volume paths', () => {
  // A path is a fact about an image. An entry with `image: null` is built from
  // source by AppCrane's own builder, which already guarantees DATA_DIR=/data.
  for (const e of CATALOG) {
    if (e.volume_paths === undefined) continue;
    assert.equal(typeof e.image, 'string',
      `${e.slug}: volume_paths without an image — nothing measured it`);
  }
});

test('the paths whose content the image ships are recorded, and are all declared', () => {
  // The seed-on-first-use handoff. A bind mount masks image content, so each
  // path here starts empty on the first boot after this change until seeding
  // lands. Shrinking this list silently is how that hazard gets lost, so the
  // count is asserted too.
  let total = 0;
  for (const [slug, paths] of Object.entries(SHIPS_CONTENT)) {
    const entry = bySlug.get(slug);
    assert.ok(entry, `catalogue lost the '${slug}' entry`);
    for (const p of paths) {
      assert.ok(entry.volume_paths.includes(p),
        `${slug}: ${p} ships content but is no longer declared — the seeding list is stale`);
      total++;
    }
  }
  assert.equal(total, 19, 'the measured seed list is 19 paths across 11 entries');
  assert.equal(Object.keys(SHIPS_CONTENT).length, 11);
  for (const slug of Object.keys(SHIPS_CONTENT)) {
    assert.ok(slug in MEASURED, `${slug} is in SHIPS_CONTENT but not in MEASURED`);
  }
});

test('the paths that hold a whole application are flagged for seeding', () => {
  // Not a re-statement of the test above: these three are the ones where an
  // empty bind mount does not degrade a feature, it stops the container. The
  // image ships the application itself at the path — 7,747 files under
  // orangehrm's /var/www/html, 22,763 under simplerisk's /var/www/simplerisk,
  // and a pre-initialised MariaDB datadir under its /var/lib/mysql. If any of
  // these ever leaves SHIPS_CONTENT, seeding stopped being required for it and
  // that needs a fresh measurement, not an edit.
  for (const [slug, path] of [
    ['orangehrm', '/var/www/html'],
    ['simplerisk', '/var/www/simplerisk'],
    ['simplerisk', '/var/lib/mysql'],
    ['erpnext', '/home/frappe/frappe-bench/sites'],
  ]) {
    assert.ok(SHIPS_CONTENT[slug].includes(path), `${slug}: ${path} left the seeding list`);
    assert.ok(bySlug.get(slug).volume_paths.includes(path),
      `${slug}: ${path} is declared nowhere, so the seeding list points at nothing`);
  }
});

test('bookstack, the entry the feature was written for, declares /config', () => {
  // The type case, kept concrete: BookStack is a linuxserver/* image and puts
  // everything it owns under /config. Before v2.70.0 that lived in the writable
  // layer and every redeploy destroyed it.
  assert.deepEqual(bySlug.get('bookstack').volume_paths, ['/config']);
  assert.ok(!('bookstack' in SHIPS_CONTENT),
    'BookStack /config is an empty directory in the image — it needs no seeding');
});
