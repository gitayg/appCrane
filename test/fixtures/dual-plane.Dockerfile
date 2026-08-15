# A container with TWO listeners, which is the whole premise of ingress_type='dual'.
#
# Deliberately not a real app: the two planes have to be distinguishable ON THE
# WIRE, so a test can prove which one a published port actually reached. The
# control plane speaks HTTP (what Caddy proxies); the data plane speaks a bare
# line protocol that is NOT HTTP, so an HTTP client cannot accidentally succeed
# against it and report a pass.
#
# alpine, and busybox nc, because the sibling live tests already pull it — no
# extra image to fetch on a runner that is already slow. `nc -l` serves one
# connection and exits, hence the loops.
FROM alpine:latest

# Shell form on purpose: PORT and DATA_PLANE_PORT arrive as container env from
# startApp, and must expand at runtime rather than at build time.
CMD sh -c '\
  while true; do \
    printf "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nCONTROL" \
      | nc -l -p "${PORT:-3000}"; \
  done & \
  while true; do \
    printf "DATAPLANE\n" | nc -l -p "${DATA_PLANE_PORT:-8081}"; \
  done'
