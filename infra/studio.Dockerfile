# Studio agent image — host environment for every Claude Code CLI run
# (Builder chat, Ask, Improve coder, planner, contextBuilder).
#
# Tag policy: appcrane-studio:latest, labeled with appcrane.studio.version.
# AppCrane's ensureStudioImage() compares that label against
# STUDIO_IMAGE_VERSION in server/services/appstudio/generator.js to decide
# whether to rebuild. Bump BOTH places when changing the recipe.
#
# Build manually (e.g. on a fresh prod host before the first user request):
#   ./scripts/build-studio-image.sh
# or directly:
#   docker build -t appcrane-studio:latest -f infra/studio.Dockerfile infra/

ARG STUDIO_IMAGE_VERSION=5

FROM node:20-alpine
ARG STUDIO_IMAGE_VERSION
LABEL appcrane.studio.version="${STUDIO_IMAGE_VERSION}"
# bash is NOT optional. node:*-alpine ships busybox `ash` as /bin/sh and no
# bash at all, and Claude Code's Bash tool spawns bash specifically -- the
# binary references /bin/bash directly. Without it EVERY shell call the agent
# makes fails at spawn:
#
#     $ bash -lc "echo hello"
#     sh: bash: not found
#
# and the model, whose only shell tool errors every time, tells the user it has
# "no shell in this environment" and hands them commands to run themselves. It
# could still read and edit files, so the session looked like it was working.
# Measured in this exact image before the fix.
RUN apk add --no-cache git bash
RUN npm install -g @anthropic-ai/claude-code
# uid/gid pinned: appContainer.js chowns the mounted transcripts to exactly
# this pair (STUDIO_UID/STUDIO_GID), so they cannot drift apart.
#
# ~/.claude is created here, owned by studio, because the transcripts are
# bind-mounted at ~/.claude/projects: without it Docker creates the parent as
# root, and Claude cannot write its own state there. Measured on a real
# instance: `mkdir ~/.claude/shell-snapshots: Permission denied`, and the agent
# told the user "Bash is blocked by an environment permission issue".
RUN addgroup -S -g 101 studio && adduser -S -u 100 -G studio studio \
    && mkdir -p /home/studio/.claude /workspace \
    && chown -R studio:studio /home/studio /workspace
USER studio
