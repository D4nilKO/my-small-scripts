#!/usr/bin/env bash
set -euo pipefail

# setup-server.sh — Ubuntu 24.04
# Interactive secure setup that:
# - prompts the operator to import an SSH key for root first (Termius etc.)
# - optionally creates a new admin user and sets a password
# - copies root authorized_keys -> new user's authorized_keys (if present and target missing)
# - optionally changes SSH port (only if provided)
# - configures UFW (allows HTTP/HTTPS and the SSH port)
# - installs and configures fail2ban with a clean sshd jail
# - optional Telegram notifications for fail2ban start/stop ONLY (no ban/unban)
# IMPORTANT: if you leave any input empty, that step will be SKIPPED (safe behavior)

# Output helpers
info(){ printf "
[INFO] %s
" "$1"; }
ok(){ printf "
[OK] %s
" "$1"; }
warn(){ printf "\n[WARN] %s\n" "$1"; }
err(){ printf "
[ERROR] %s
" "$1"; }
confirm(){ read -r -p "$1" ans; [[ "$ans" =~ ^[Yy]$ ]]; }

# Must be run as root
if [[ $(id -u) -ne 0 ]]; then
  err "Run this script as root or with sudo."; exit 2
fi

# Remind operator to import root public key
cat <<'MSG'

=== IMPORTANT ===
Before you continue, please import your public SSH key into /root/.ssh/authorized_keys
(e.g. using Termius -> Upload public key). This script will, if you choose, copy that
key to the new user's ~/.ssh/authorized_keys so you can immediately login as that user.
If you haven't imported the key yet — do it now, then run the script again. Or answer 'y'
below to continue at your own risk.
MSG

if ! [[ -f /root/.ssh/authorized_keys ]]; then
  if ! confirm "Have you uploaded the public key to /root/.ssh/authorized_keys? (y/N): "; then
    warn "OK — import the key and re-run the script. Exiting."; exit 0
  fi
fi

# Ask for parameters (empty = skip that step)
read -r -p "New admin username (leave empty to SKIP creating user): " USERNAME
USERNAME="${USERNAME:-}"

PASS=""
if [[ -n "$USERNAME" ]]; then
  read -s -r -p "Password for $USERNAME (leave empty to NOT set password): " PASS
  echo
fi

read -r -p "New SSH port (1025-65000) (leave empty to SKIP changing port): " SSH_PORT
SSH_PORT="${SSH_PORT:-}"
if [[ -n "$SSH_PORT" && ! "$SSH_PORT" =~ ^[0-9]+$ ]]; then
  err "SSH port must be a number. Exiting."; exit 3
fi

read -r -p "Apply SSH hardening (disable root/password login)? (y/N): " APPLY_HARDENING
APPLY_HARDENING="${APPLY_HARDENING:-n}"

read -r -p "Server tag for Telegram messages (leave empty to skip): " SERVER_TAG
SERVER_TAG="${SERVER_TAG:-}"

read -r -p "Enable Telegram notifications for fail2ban (start/stop only)? (y/N): " USE_TG
USE_TG="${USE_TG:-n}"
TG_TOKEN=""; TG_CHAT_ID=""
if [[ "$USE_TG" =~ ^[Yy]$ ]]; then
  read -r -p "Telegram Bot Token: " TG_TOKEN
  read -r -p "Telegram Chat ID: " TG_CHAT_ID
  if [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]]; then
    warn "Telegram token/chat missing — Telegram will be disabled."; USE_TG="n"
  fi
fi

# Summarize and confirm
info "Summary of actions (empty = will be skipped):"
echo " - Create user: ${USERNAME:-<skip>}"
echo " - Set password: $( [[ -n "$PASS" ]] && echo 'yes' || echo 'no')"
echo " - Change SSH port: ${SSH_PORT:-<skip>}"
echo " - Apply SSH hardening: ${APPLY_HARDENING:-no}"
echo " - Server tag: ${SERVER_TAG:-<none>}"
echo " - Telegram enabled: $([[ "$USE_TG" =~ ^[Yy]$ ]] && echo YES || echo NO)"
if ! confirm "Proceed and apply changes? (y/N): "; then info "Aborted by user."; exit 0; fi

# Update packages list
info "Updating package lists..."
apt-get update -y >/dev/null

# Create user if requested
STEP_USER_CREATED=0
if [[ -n "$USERNAME" ]]; then
  if id -u "$USERNAME" >/dev/null 2>&1; then
    warn "User $USERNAME already exists; skipping creation."
  else
    info "Creating user $USERNAME..."
    adduser --disabled-password --gecos "" "$USERNAME" >/dev/null
    usermod -aG sudo,adm "$USERNAME"
    # Standard sudo access (password required)
    # Passwordless sudo can be added manually if needed
    STEP_USER_CREATED=1
    ok "User $USERNAME created and added to sudo."
  fi

  if [[ -n "$PASS" ]]; then
    info "Setting password for $USERNAME..."
    printf '%s:%s
' "$USERNAME" "$PASS" | chpasswd
    ok "Password set for $USERNAME."
  fi

  # Copy root keys if present and target not present
  if [[ -f /root/.ssh/authorized_keys ]]; then
    mkdir -p "/home/${USERNAME}/.ssh"
    if [[ -f "/home/${USERNAME}/.ssh/authorized_keys" ]]; then
      warn "/home/${USERNAME}/.ssh/authorized_keys exists — will NOT overwrite."
    else
      info "Copying root's authorized_keys -> /home/${USERNAME}/.ssh/authorized_keys"
      cp /root/.ssh/authorized_keys "/home/${USERNAME}/.ssh/authorized_keys"
      chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}/.ssh"
      chmod 700 "/home/${USERNAME}/.ssh"
      chmod 600 "/home/${USERNAME}/.ssh/authorized_keys"
      ok "SSH key copied to ${USERNAME}. You can now login as $USERNAME."
    fi
  else
    warn "/root/.ssh/authorized_keys not found — no keys copied to new user."
  fi
fi

# Install ufw, fail2ban, curl
info "Installing required packages: ufw, fail2ban, curl..."
apt-get install -y ufw fail2ban curl >/dev/null
ok "Packages installed."

# Configure UFW: ensure HTTP/HTTPS allowed and SSH port allowed (22 if not changed)
info "Configuring UFW (allow SSH, HTTP, HTTPS)..."
ufw --force default deny incoming >/dev/null || true
ufw --force default allow outgoing >/dev/null || true
ufw allow 80/tcp >/dev/null || true
ufw allow 443/tcp >/dev/null || true
if [[ -n "$SSH_PORT" ]]; then
  ufw allow "${SSH_PORT}/tcp" >/dev/null || true
  ok "Allowed SSH port ${SSH_PORT} through UFW."
else
  ufw allow 22/tcp >/dev/null || true
  ok "Allowed SSH port 22 through UFW (no change requested)."
fi
ufw --force enable >/dev/null || true

# Backup sshd_config before changing
SSHD_CFG="/etc/ssh/sshd_config"
SSHD_BACKUP="${SSHD_CFG}.bak.$(date +%s)"
cp -a "$SSHD_CFG" "$SSHD_BACKUP"
info "Backed up sshd_config -> $SSHD_BACKUP"

# Helper to set or replace a key in sshd_config
set_sshd() {
  local key="$1" val="$2"
  if grep -qE "^[#[:space:]]*${key}" "$SSHD_CFG"; then
    sed -ri "s|^[#[:space:]]*(${key}).*|\1 ${val}|" "$SSHD_CFG"
  else
    echo "${key} ${val}" >> "$SSHD_CFG"
  fi
}

SSH_CHANGED=0

# Apply SSH hardening independently
if [[ "$APPLY_HARDENING" =~ ^[Yy]$ ]]; then
  info "Applying SSH hardening (key-only, no root/password)..."
  set_sshd "PermitRootLogin" "no"
  set_sshd "PasswordAuthentication" "no"
  set_sshd "KbdInteractiveAuthentication" "no"
  set_sshd "ChallengeResponseAuthentication" "no"
  set_sshd "PubkeyAuthentication" "yes"
  set_sshd "UsePAM" "yes"
  set_sshd "PermitEmptyPasswords" "no"
  SSH_CHANGED=1
fi

# Apply SSH port change independently
if [[ -n "$SSH_PORT" ]]; then
  if (( SSH_PORT < 1025 || SSH_PORT > 65000 )); then
    err "SSH port must be between 1025 and 65000. Exiting."; exit 4
  fi
  info "Setting SSH Port=${SSH_PORT}..."
  set_sshd "Port" "$SSH_PORT"
  SSH_CHANGED=1
fi

[[ $SSH_CHANGED -eq 0 ]] && info "No SSH changes requested; sshd_config untouched."

# If we changed SSH config ensure UFW has the rule (already added) and test config then restart
if [[ $SSH_CHANGED -eq 1 ]]; then
  info "Testing sshd configuration..."
  if sshd -t; then
    info "sshd config OK — restarting ssh service..."
    systemctl restart ssh || systemctl restart sshd
    ok "SSH restarted."
  else
    warn "sshd -t FAILED — restoring backup and aborting ssh restart."
    cp -a "$SSHD_BACKUP" "$SSHD_CFG"
    systemctl restart ssh || true
    err "sshd config had errors; restored backup $SSHD_BACKUP. Please inspect /etc/ssh/sshd_config"
  fi
fi

# --- Configure fail2ban ---
info "Configuring fail2ban..."
# Prepare jail file with explicit 'port' and multi-line action (no trailing commas)
F2B_JAIL_FILE="/etc/fail2ban/jail.d/99-sshd.conf"
PORT_FOR_JAIL="${SSH_PORT:-ssh}"
cat > "$F2B_JAIL_FILE" <<EOF
[sshd]
enabled = true
port = ${PORT_FOR_JAIL}
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
bantime = 3600
action = nftables-multiport
EOF
ok "Wrote fail2ban jail: $F2B_JAIL_FILE"

# --- Telegram notifier script for start/stop only (if requested) ---
if [[ "$USE_TG" =~ ^[Yy]$ ]]; then
  info "Configuring Telegram notifier (start/stop only)..."
  
  # notifier that is safe (always exits 0)
  cat > /usr/local/bin/fail2ban_notify.sh <<EOF
#!/usr/bin/env bash
TOKEN="${TG_TOKEN}"
CHAT_ID="${TG_CHAT_ID}"
TAG="${SERVER_TAG}"
ACTION="\$1"
IP="\$2"
JAIL="\$3"
if [[ -z "\$TOKEN" || -z "\$CHAT_ID" ]]; then
  exit 0
fi
case "\$ACTION" in
  start)
    curl -s -X POST "https://api.telegram.org/bot\${TOKEN}/sendMessage" -d chat_id="\${CHAT_ID}" -d text="[⚙️] \${TAG:-server}: Fail2Ban started" >/dev/null 2>&1 || true
    ;;
  stop)
    curl -s -X POST "https://api.telegram.org/bot\${TOKEN}/sendMessage" -d chat_id="\${CHAT_ID}" -d text="[❌] \${TAG:-server}: Fail2Ban stopped" >/dev/null 2>&1 || true
    ;;
  *)
    ;;
esac
exit 0
EOF
  chmod +x /usr/local/bin/fail2ban_notify.sh

  # systemd drop-in
  mkdir -p /etc/systemd/system/fail2ban.service.d
  cat > /etc/systemd/system/fail2ban.service.d/notify.conf <<EOF
[Service]
ExecStartPost=/usr/local/bin/fail2ban_notify.sh start
ExecStopPost=/usr/local/bin/fail2ban_notify.sh stop
EOF
  systemctl daemon-reload || true
  ok "Telegram notifier installed (start/stop only)."
else
  info "Telegram not enabled; skipping Telegram notifier."
fi

# Ensure fail2ban installed and restart
info "Enabling and restarting fail2ban..."
systemctl enable --now fail2ban || true
sleep 1
if systemctl is-active --quiet fail2ban; then
  ok "fail2ban is active."
else
  warn "fail2ban failed to start. Check logs: journalctl -u fail2ban -n 200 --no-pager"
fi

# If Telegram enabled, send a test message (start notification)
if [[ "$USE_TG" =~ ^[Yy]$ ]]; then
  info "Sending Telegram test message..."
  /usr/local/bin/fail2ban_notify.sh start || true
  ok "Telegram test executed (check your chat)."
fi

# Final summary and quick test instructions
info "Setup finished. Summary:"
echo " - User created: ${STEP_USER_CREATED:+YES}${STEP_USER_CREATED:-NO}"
echo " - SSH changed: ${SSH_CHANGED:+YES}${SSH_CHANGED:-NO} (port: ${SSH_PORT:-default})"
echo " - UFW: HTTP/HTTPS allowed; SSH allowed on ${SSH_PORT:-22}"
echo " - fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')"
echo " - Telegram: $([[ "$USE_TG" =~ ^[Yy]$ ]] && echo 'ENABLED (start/stop only)' || echo 'DISABLED')"

echo
info "Quick test commands (run from server):"
echo " - Check fail2ban status: sudo systemctl status fail2ban -l"
echo " - List jails: sudo fail2ban-client status"
echo " - List sshd jail: sudo fail2ban-client status sshd"
echo " - Ban test IP (safe TEST-NET): sudo fail2ban-client set sshd banip 203.0.113.5"
echo " - Unban test IP: sudo fail2ban-client set sshd unbanip 203.0.113.5"

echo
ok "All done. If anything failed, check logs: journalctl -u fail2ban -n 200 --no-pager"