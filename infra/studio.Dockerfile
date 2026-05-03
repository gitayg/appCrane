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

ARG STUDIO_IMAGE_VERSION=3

FROM node:20-alpine
ARG STUDIO_IMAGE_VERSION
LABEL appcrane.studio.version="${STUDIO_IMAGE_VERSION}"
RUN apk add --no-cache git
RUN npm install -g @anthropic-ai/claude-code
RUN addgroup -S studio && adduser -S -G studio studio \
    && mkdir -p /home/studio /workspace \
    && chown studio:studio /home/studio /workspace
USER studio
