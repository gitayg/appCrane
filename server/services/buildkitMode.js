import { dockerBuildEnv } from './docker.js';

// Whether `docker build` will run with BuildKit, read from the same
// environment docker.js hands the build (dockerBuildEnv). The Docker CLI parses
// DOCKER_BUILDKIT as a Go boolean, so only these spellings turn it on.
const TRUE_VALUES = new Set(['1', 't', 'T', 'true', 'TRUE', 'True']);

export function buildKitEnabled(env = dockerBuildEnv()) {
  return TRUE_VALUES.has(String(env.DOCKER_BUILDKIT ?? ''));
}
