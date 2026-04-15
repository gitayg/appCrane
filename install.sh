#!/usr/bin/env bash
#
# AppCrane installer for fresh Ubuntu servers.
#
# Interactive:
#   curl -fsSL https://raw.githubusercontent.com/gitayg/appCrane/main/install.sh | sudo bash
#   sudo bash install.sh
#
# Non-interactive (CI / automation):
#   sudo CRANE_DOMAIN=crane.example.com \
#        ADMIN_EMAIL=admin@example.com \
#        bash install.sh
#
#   Or via flags:
#   sudo bash install.sh --domain crane.example.com \
#                        --admin-email admin@example.com \
#                        --admin-name "Admin" \
#                        --tls-cert /etc/caddy/certs/fullchain.pem \
#                        --tls-key  /etc/caddy/certs/privkey.pem
#
# --tls-cert / --tls-key: skip ACME and use a pre-provisioned cert (required for
#   HSTS-preloaded domains where browsers block HTTP challenges).
#
# Flags override env vars. ADMIN_NAME defaults to "admin" when not set.
# Re-running is safe — every step is idempotent.

set -euo pipefail

NODE_MAJOR=20
REPO_URL="https://github.com/gitayg/appCrane.git"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

# --- flag parsing (override env vars when provided) ----------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)       CRANE_DOMAIN="${2:?--domain requires a value}";     shift 2 ;;
    --admin-email)  ADMIN_EMAIL="${2:?--admin-email requires a value}";  shift 2 ;;
    --admin-name)   ADMIN_NAME="${2:?--admin-name requires a value}";    shift 2 ;;
    --tls-cert)     TLS_CERT_FILE="${2:?--tls-cert requires a value}";   shift 2 ;;
    --tls-key)      TLS_KEY_FILE="${2:?--tls-key requires a value}";     shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) die "Unknown flag: $1  (supported: --domain, --admin-email, --admin-name, --tls-cert, --tls-key)" ;;
  esac
done

# ---------- pre-flight ---------------------------------------------------

[[ "$(uname -s)" == "Linux" ]] || die "This installer targets Linux. Detected: $(uname -s)"
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

RUN_USER="${SUDO_USER:-root}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
[[ -n "$RUN_HOME" ]] || die "Could not resolve home directory for $RUN_USER"

# If we're inside an existing checkout, install from here. Otherwise clone.
if [[ -f "$(dirname "${BASH_SOURCE[0]}")/package.json" ]]; then
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  REPO_DIR="$RUN_HOME/appCrane"
fi

log "Install user: $RUN_USER ($RUN_HOME)"
log "Repo dir:     $REPO_DIR"

# ---------- system packages ----------------------------------------------

log "Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates gnupg lsb-release git build-essential \
  debian-keyring debian-archive-keyring apt-transport-https jq

# ---------- Node.js ------------------------------------------------------

if ! command -v node >/dev/null 2>&1 || [[ "$(node -v | sed 's/v//;s/\..*//')" -lt $NODE_MAJOR ]]; then
  log "Installing Node.js ${NODE_MAJOR}.x"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
else
  log "Node $(node -v) already installed"
fi

# ---------- Caddy --------------------------------------------------------

if ! command -v caddy >/dev/null 2>&1; then
  log "Installing Caddy"
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
else
  log "Caddy already installed"
fi

systemctl enable --now caddy

if ! curl -fsS http://localhost:2019/config/ >/dev/null 2>&1; then
  warn "Caddy admin API not reachable at :2019 — AppCrane needs it for routing."
  warn "Check 'systemctl status caddy'."
fi

# ENH-002: Caddy file permissions + sudoers so AppCrane can manage Caddy
log "Configuring Caddy permissions for $RUN_USER"
mkdir -p /etc/caddy/sites
if ! getent group caddy >/dev/null 2>&1; then
  groupadd --system caddy
fi
usermod -aG caddy "$RUN_USER" 2>/dev/null || true
chown root:caddy /etc/caddy /etc/caddy/sites
chmod 775 /etc/caddy /etc/caddy/sites
[[ -f /etc/caddy/Caddyfile ]] && chown root:caddy /etc/caddy/Caddyfile && chmod 664 /etc/caddy/Caddyfile

SUDOERS_FILE="/etc/sudoers.d/appcrane-caddy"
cat > "$SUDOERS_FILE" <<SUDOERS
# Allow AppCrane runtime user to reload/restart Caddy without a password
${RUN_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload caddy
${RUN_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart caddy
SUDOERS
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" || { rm -f "$SUDOERS_FILE"; warn "sudoers file invalid — Caddy reload will require manual intervention"; }
log "Sudoers written: $SUDOERS_FILE"

# ---------- Docker + systemd (shared logic, reused by self-update) -------
# install.sh calls the upgrade script AFTER the repo is cloned so the script is present.

# ---------- clone / install repo -----------------------------------------

if [[ ! -d "$REPO_DIR/.git" ]]; then
  log "Cloning AppCrane to $REPO_DIR"
  sudo -u "$RUN_USER" -H git clone "$REPO_URL" "$REPO_DIR"
fi

log "Installing npm dependencies"
sudo -u "$RUN_USER" -H bash -c "cd '$REPO_DIR' && npm install"

log "Linking 'crane' CLI globally"
( cd "$REPO_DIR" && npm link )

# ---------- .env ---------------------------------------------------------

ENV_FILE="$REPO_DIR/.env"

# ask VAR "Prompt text" [default]
# Uses the value already in $VAR (set via env or flag) without prompting.
# Falls back to default without prompting when no TTY is available.
# Only opens /dev/tty when a value is genuinely needed interactively.
ask() {
  local var="$1" prompt="$2" default="${3:-}" val
  # Already provided via env var or flag — use it as-is.
  val="${!var:-}"
  if [[ -n "$val" ]]; then
    log "  $prompt: $val"
    printf -v "$var" '%s' "$val"
    return
  fi
  # No value — use default silently if no TTY (non-interactive mode).
  if [[ -n "$default" ]] && [[ ! -e /dev/tty ]]; then
    printf -v "$var" '%s' "$default"
    return
  fi
  # Interactive prompt — requires a TTY.
  [[ -e /dev/tty ]] || die "No TTY and \$$var not set. Pass via env or flag: $var=... bash install.sh  or  --$(echo "$var" | tr '[:upper:]_' '[:lower:]-') VALUE"
  while :; do
    if [[ -n "$default" ]]; then
      printf '%s [%s]: ' "$prompt" "$default" > /dev/tty
    else
      printf '%s: ' "$prompt" > /dev/tty
    fi
    IFS= read -r val < /dev/tty || val=""
    val="${val:-$default}"
    [[ -n "$val" ]] && { printf -v "$var" '%s' "$val"; return; }
    printf '  (required)\n' > /dev/tty
  done
}

if [[ ! -f "$ENV_FILE" ]]; then
  log "Creating .env"

  ask CRANE_DOMAIN "AppCrane domain (e.g. crane.example.com)"

  ENCRYPTION_KEY="$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"

  cat > "$ENV_FILE" <<EOF
PORT=5001
HOST=0.0.0.0

# DO NOT lose this key — env vars cannot be decrypted without it.
ENCRYPTION_KEY=${ENCRYPTION_KEY}

SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=appcrane@${CRANE_DOMAIN}

CRANE_DOMAIN=${CRANE_DOMAIN}

# Optional: provide manual TLS cert/key to skip ACME (required for HSTS-preloaded domains)
TLS_CERT_FILE=${TLS_CERT_FILE:-}
TLS_KEY_FILE=${TLS_KEY_FILE:-}

CADDY_ADMIN_URL=http://localhost:2019
DATA_DIR=${REPO_DIR}/data
EOF
  chown "$RUN_USER":"$RUN_USER" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  log ".env written (chmod 600)"
else
  log ".env already exists — leaving untouched"
fi

# ---------- Docker + systemd setup (idempotent) --------------------------

log "Running Docker/systemd setup"
bash "$REPO_DIR/scripts/upgrade-to-docker.sh" full "$REPO_DIR" "$RUN_USER"

# Wait for the API to come up.
for _ in {1..20}; do
  curl -fsS http://localhost:5001/api/health >/dev/null 2>&1 && break
  sleep 0.5
done

# ---------- admin init ---------------------------------------------------

CONFIG_FILE="$RUN_HOME/.appcrane/config.json"
if [[ -f "$CONFIG_FILE" ]] && jq -e .key "$CONFIG_FILE" >/dev/null 2>&1; then
  log "Admin already initialized — skipping crane init"
else
  ask ADMIN_NAME  "Admin name" "admin"
  ask ADMIN_EMAIL "Admin email"

  log "Initializing admin user"
  sudo -u "$RUN_USER" -H crane init --name "$ADMIN_NAME" --email "$ADMIN_EMAIL"
fi

# ---------- done ---------------------------------------------------------

cat <<EOF

$(printf '\033[1;32mAppCrane is up.\033[0m')

  API:        http://localhost:5001
  Domain:     https://${CRANE_DOMAIN:-<set in .env>}
  Admin key:  $CONFIG_FILE
  systemd:    systemctl status appcrane | journalctl -u appcrane -f
  Docker:     docker ps --filter label=appcrane=true

Next:
  1. Point DNS for ${CRANE_DOMAIN:-your crane domain} at this server.
  2. crane app create --name MyApp --slug myapp --repo https://github.com/...
     → reachable at https://${CRANE_DOMAIN:-your crane domain}/myapp
  3. Back up ${ENV_FILE} — losing ENCRYPTION_KEY bricks every stored env var.
EOF
