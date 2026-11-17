// A catalogue entry's `build` recipe: how AppCrane builds an app from its
// repository when the project ships no Dockerfile, no image and no
// deployhub.json, so the generated Node build would otherwise guess wrong.
//
//   install  replaces `npm ci --omit=dev` (a Next.js build needs its devDependencies)
//   build    replaces the detected `npm run build`
//   start    replaces the detected `npm start`; runs on every container start,
//            so a migration step belongs here (e.g. `node db/migrate.mjs && npm start`)
//   env      fixed, non-secret defaults written as ENV into the generated
//            Dockerfile; a value set on the app's environment still wins
//
// The repo keeps the last word: whatever its own deployhub.json declares
// (be.entry, fe.build, be.install, be.health) is used instead of the recipe,
// and an app-provided Dockerfile skips the generator, and so the recipe, entirely.

import { findEntry } from './catalogService.js';

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const COMMAND_KEYS = ['install', 'build', 'start'];

/** Throws on a recipe the generator could not use safely. Returns it. */
export function validateRecipe(recipe) {
  if (!recipe || typeof recipe !== 'object' || Array.isArray(recipe)) throw new Error('build must be an object');
  for (const k of Object.keys(recipe)) {
    if (![...COMMAND_KEYS, 'env'].includes(k)) throw new Error(`build.${k} is not a recipe field`);
  }
  for (const k of COMMAND_KEYS) {
    if (recipe[k] === undefined) continue;
    if (typeof recipe[k] !== 'string' || !recipe[k].trim()) throw new Error(`build.${k} must be a non-empty string`);
    if (/[\r\n]/.test(recipe[k])) throw new Error(`build.${k} must be one line`);
  }
  if (recipe.env !== undefined) {
    if (!recipe.env || typeof recipe.env !== 'object' || Array.isArray(recipe.env)) throw new Error('build.env must be an object');
    for (const [k, v] of Object.entries(recipe.env)) {
      if (!ENV_NAME_RE.test(k)) throw new Error(`build.env key ${JSON.stringify(k)} is not a variable name`);
      if (typeof v !== 'string' || /["\\$\r\n]/.test(v)) throw new Error(`build.env.${k} must be a string without quotes, backslashes, $ or newlines`);
    }
  }
  return recipe;
}

/** The recipe that applies to this deploy, or null. */
export function catalogRecipeFor(app, isImageDeploy) {
  if (isImageDeploy || !app?.catalog_slug) return null;
  const entry = findEntry(app.catalog_slug);
  if (!entry?.build) return null;
  return { recipe: validateRecipe(entry.build), entry };
}

export function recipeEnvLines(recipe) {
  const env = recipe?.env;
  if (!env || !Object.keys(env).length) return [];
  return [...Object.entries(env).map(([k, v]) => `ENV ${k}="${v}"`), ''];
}

/**
 * The entry's `health` becomes the release's be.health when the repo's own
 * deployhub.json names none, so the deploy gate and the health checker both
 * probe it. Returns true when it did.
 */
export function applyRecipeHealth(manifest, entry) {
  if (manifest?.be?.health || typeof entry?.health !== 'string' || !entry.health) return false;
  manifest.be = { ...(manifest.be || {}), health: entry.health };
  return true;
}
