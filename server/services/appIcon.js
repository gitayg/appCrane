import { copyFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { regularFileInside } from '../utils/paths.js';

// Deploy-time pickup of an icon committed at public/icon.<ext> (v2.5.22): copied
// to <DATA_DIR>/apps/<slug>/icon.<ext>, the path the dashboard upload writes
// and GET /api/apps/:slug/icon serves without authentication.
//
// The source must be a regular file in the release tree, never a link. A
// release dir is a git checkout and git checks a committed symlink out as one,
// so `public/icon.png -> /root/appCrane/.env` was copied and then published at
// the icon URL (utils/paths.js).

export const ICON_PREFERENCE = ['png', 'svg', 'webp', 'jpg', 'jpeg', 'gif'];

/** The extension picked up, or null when the release ships no usable icon. */
export function pickUpAppIcon({ releaseDir, dataDir, slug }) {
  const found = ICON_PREFERENCE
    .map(ext => ({ ext, path: join(releaseDir, 'public', `icon.${ext}`) }))
    .find(({ path }) => regularFileInside(releaseDir, path));
  if (!found) return null;
  const appIconDir = join(dataDir, 'apps', slug);
  mkdirSync(appIconDir, { recursive: true });
  // Stale icons under another extension would keep being served first.
  for (const oldExt of ICON_PREFERENCE) {
    if (oldExt === found.ext) continue;
    const oldPath = join(appIconDir, `icon.${oldExt}`);
    if (existsSync(oldPath)) {
      try { unlinkSync(oldPath); } catch (_) {}
    }
  }
  // A copy, not a rename: the source belongs to the release dir.
  copyFileSync(found.path, join(appIconDir, `icon.${found.ext}`));
  return found.ext;
}
