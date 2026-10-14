#!/usr/bin/env bash
# harden.sh — baseline security for a fresh Ubuntu 22.04 / 24.04 web server.
#
#   sudo ./harden.sh --user deploy --pubkey-file ~/.ssh/id_ed25519.pub
#
# Safe to run more than once. Use --dry-run to see what would change.
set -euo pipefail

USER_NAME=""
PUBKEY=""
SSH_PORT=22
WEB=true
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: sudo ./harden.sh --user NAME (--pubkey "ssh-ed25519 AAAA..." | --pubkey-file FILE) [options]

Options:
  --user NAME          Admin user to create (or reuse). Root login is disabled afterwards.
  --pubkey KEY         SSH public key allowed to log in as NAME.
  --pubkey-file FILE   Read the public key from FILE.
  --ssh-port PORT      SSH port to allow and listen on (default 22).
  --no-web             Do not open ports 80 and 443.
  --dry-run            Print the changes without applying them.
  -h, --help           Show this help.
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }

# Run a command, or only print it in dry-run mode.
run() {
  if $DRY_RUN; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

# write_file PATH MODE  (content on stdin)
write_file() {
  local path=$1 mode=$2 content
  content=$(cat)
  if $DRY_RUN; then
    printf '[dry-run] write %s (%s):\n%s\n' "$path" "$mode" "$content"
    return
  fi
  install -d "$(dirname "$path")"
  printf '%s\n' "$content" >"$path"
  chmod "$mode" "$path"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_NAME=${2:-}; shift 2 ;;
    --pubkey) PUBKEY=${2:-}; shift 2 ;;
    --pubkey-file) [[ -r ${2:-} ]] || die "cannot read ${2:-}"; PUBKEY=$(<"$2"); shift 2 ;;
    --ssh-port) SSH_PORT=${2:-}; shift 2 ;;
    --no-web) WEB=false; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

# ---------------------------------------------------------------- checks
[[ -n $USER_NAME ]] || { usage; die "--user is required"; }
[[ $USER_NAME =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid user name: $USER_NAME"
[[ $USER_NAME != root ]] || die "--user must not be root"
[[ $PUBKEY =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com)\  ]] || die "--pubkey does not look like an SSH public key"
if ! [[ $SSH_PORT =~ ^[0-9]+$ ]] || ((SSH_PORT < 1 || SSH_PORT > 65535)); then
  die "invalid --ssh-port: $SSH_PORT"
fi
$DRY_RUN || [[ $EUID -eq 0 ]] || die "run as root (sudo), or use --dry-run"
# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || die "this script supports Ubuntu only (found: ${ID:-unknown})"

export DEBIAN_FRONTEND=noninteractive

OPEN_PORTS="$SSH_PORT/tcp"
$WEB && OPEN_PORTS+=", 80/tcp and 443/tcp"

# ---------------------------------------------------------------- packages
log "Installing security packages"
run apt-get update -q
run apt-get install -y -q openssh-server ufw fail2ban python3-systemd unattended-upgrades

# ---------------------------------------------------------------- admin user
log "Admin user: $USER_NAME"
if id "$USER_NAME" >/dev/null 2>&1; then
  echo "user exists"
else
  run adduser --disabled-password --gecos "" "$USER_NAME"
fi
run usermod -aG sudo "$USER_NAME"

HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6 || true)
HOME_DIR=${HOME_DIR:-/home/$USER_NAME}
AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
run install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh"
if ! $DRY_RUN && grep -qxF "$PUBKEY" "$AUTH_KEYS" 2>/dev/null; then
  echo "public key already authorized"
elif $DRY_RUN; then
  echo "[dry-run] append public key to $AUTH_KEYS"
else
  printf '%s\n' "$PUBKEY" >>"$AUTH_KEYS"
fi
run chown "$USER_NAME:$USER_NAME" "$AUTH_KEYS"
run chmod 600 "$AUTH_KEYS"

# A user created without a password could not use sudo once root login is off.
PASS_STATE=$(passwd -S "$USER_NAME" 2>/dev/null | awk '{print $2}' || true)
if [[ $PASS_STATE != P ]]; then
  echo "$USER_NAME has no password: allowing passwordless sudo (set one with 'passwd $USER_NAME' and delete /etc/sudoers.d/90-$USER_NAME to require it)"
  write_file "/etc/sudoers.d/90-$USER_NAME" 440 <<EOF
$USER_NAME ALL=(ALL) NOPASSWD:ALL
EOF
  $DRY_RUN || visudo -cqf "/etc/sudoers.d/90-$USER_NAME" || die "invalid sudoers file"
fi

# Lock-out guard: never disable passwords unless a key is in place.
$DRY_RUN || [[ -s $AUTH_KEYS ]] || die "$AUTH_KEYS is empty; refusing to disable password login"

# ---------------------------------------------------------------- SSH
log "SSH: keys only, no root login, port $SSH_PORT"
# sshd keeps the FIRST value it reads and Ubuntu includes sshd_config.d/*.conf
# in lexical order, so "00-" wins over cloud-init's "50-cloud-init.conf".
write_file /etc/ssh/sshd_config.d/00-hardening.conf 644 <<EOF
# Managed by harden.sh
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
EOF

if ! $DRY_RUN; then
  install -d -m 755 /run/sshd
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/00-hardening.conf
    die "sshd rejected the new configuration; it was removed and SSH was not restarted"
  fi
fi
# Ubuntu 24.04 uses socket activation: the listening port comes from ssh.socket.
if systemctl list-unit-files ssh.socket >/dev/null 2>&1 && systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
  run systemctl daemon-reload
  run systemctl restart ssh.socket
fi
run systemctl restart ssh

# ---------------------------------------------------------------- firewall
log "Firewall: deny incoming, allow $OPEN_PORTS"
run ufw default deny incoming
run ufw default allow outgoing
run ufw allow "$SSH_PORT/tcp"
if $WEB; then
  run ufw allow 80/tcp
  run ufw allow 443/tcp
fi
run ufw --force enable

# ---------------------------------------------------------------- updates
log "Automatic security updates"
write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ---------------------------------------------------------------- fail2ban
log "fail2ban for SSH"
write_file /etc/fail2ban/jail.d/sshd.local 644 <<EOF
[sshd]
enabled  = true
port     = $SSH_PORT
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
run systemctl enable fail2ban
run systemctl restart fail2ban

# ---------------------------------------------------------------- summary
log "Done"
cat <<EOF
  - $USER_NAME can log in with the given SSH key and use sudo
  - root login and password login over SSH are disabled (port $SSH_PORT)
  - firewall allows only $OPEN_PORTS
  - security updates install automatically; fail2ban bans repeated SSH failures

Before closing this session, open a NEW terminal and check:
  ssh -p $SSH_PORT $USER_NAME@<server>
EOF
