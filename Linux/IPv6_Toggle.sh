#!/bin/bash
set -euo pipefail

echo "=== IPv6 toggle script for Ubuntu 22.04 and 24.04 ==="

have_tty() {
    [[ -t 0 ]] || [[ -e /dev/tty ]]
}

read_line_safe() {
    # Usage: read_line_safe VAR_NAME "prompt text"
    local __var="$1"
    local __prompt="$2"
    local __ans=""

    echo
    echo -n "${__prompt}"

    # If stdin is a TTY, read normally.
    if [[ -t 0 ]]; then
        if read -r __ans; then
            :
        else
            __ans=""
        fi
    # If stdin is not a TTY (e.g. curl|bash), try reading from /dev/tty.
    elif [[ -e /dev/tty ]]; then
        if read -r __ans </dev/tty; then
            :
        else
            __ans=""
        fi
    else
        # No tty available (non-interactive environment)
        __ans=""
    fi

    printf -v "${__var}" '%s' "${__ans}"
}

ask_yes_no() {
    # Usage: ask_yes_no "Question?"  -> returns 0 if yes, 1 otherwise
    local question="$1"
    local reply=""

    read_line_safe reply "${question} [y/N] "
    [[ "${reply,,}" == "y" ]]
}

# ---------- DNS order helpers ----------
backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        sudo cp -a "$f" "${f}.bak_$(date +%Y%m%d%H%M%S)"
    fi
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
    [[ "$1" == *:* ]]
}


reorder_dns_tokens() {
    local raw="$1"
    raw="$(echo "$raw" | xargs || true)"

    local -a ipv4s=()
    local -a ipv6s=()
    local -a others=()

    local token base
    for token in $raw; do
        base="${token%%#*}"
        if is_ipv4 "$base"; then
            ipv4s+=("$token")
        elif is_ipv6 "$base"; then
            ipv6s+=("$token")
        else
            others+=("$token")
        fi
    done

    echo "${ipv4s[*]} ${ipv6s[*]} ${others[*]}" | xargs || true
}

fix_resolved_conf_dns_order() {
    local f="/etc/systemd/resolved.conf"
    [[ -f "$f" ]] || return 0

    local tmp
    tmp="$(mktemp)"

    local in_resolve=0
    local changed=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[Resolve\] ]]; then
            in_resolve=1
        elif [[ "$line" =~ ^\[[^]]+\] ]]; then
            in_resolve=0
        fi

        if (( in_resolve )) && [[ "$line" =~ ^[[:space:]]*DNS= ]] && [[ ! "$line" =~ ^[[:space:]]*# ]]; then
            local prefix val comment val_part newval
            prefix="${line%%DNS=*}"
            val="${line#*DNS=}"

            if [[ "$val" == *" #"* ]]; then
                val_part="${val%% \#*}"
                comment="${val#"$val_part"}"
            else
                val_part="$val"
                comment=""
            fi

            val_part="$(echo "$val_part" | xargs || true)"

            # если DNS= пустой — не трогаем
            if [[ -n "$val_part" ]]; then
                if echo "$val_part" | grep -Eq '(^|[[:space:]])([0-9]{1,3}\.){3}[0-9]{1,3}([#][^[:space:]]+)?([[:space:]]|$)' \
                   && echo "$val_part" | grep -Eq '(^|[[:space:]])[^[:space:]]*:[^[:space:]]*([#][^[:space:]]+)?([[:space:]]|$)'; then
                    newval="$(reorder_dns_tokens "$val_part")"
                    if [[ "$val_part" != "$newval" ]]; then
                        line="${prefix}DNS=${newval}${comment}"
                        changed=1
                    fi
                fi
            fi
        fi

        echo "$line" >> "$tmp"
    done < "$f"

    if (( changed )); then
        backup_file "$f"
        sudo cp -f "$tmp" "$f"
        echo "[OK] Reordered DNS in $f (IPv4 first)."
    else
        echo "[SKIP] $f: no mixed IPv4+IPv6 active DNS= line to reorder (or already ok)."
    fi

    rm -f "$tmp"
}

fix_resolv_conf_dns_order() {
    local f="/etc/resolv.conf"
    [[ -e "$f" ]] || return 0

    if [[ -L "$f" ]]; then
        echo "[SKIP] $f is a symlink (likely systemd-resolved stub). Not touching."
        return 0
    fi

    if grep -Eq '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.53([[:space:]]|$)' "$f"; then
        echo "[SKIP] $f uses stub 127.0.0.53. Not touching."
        return 0
    fi

    if ! grep -Eq '^[[:space:]]*nameserver[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}([[:space:]]|$)' "$f"; then
        echo "[SKIP] $f: no IPv4 nameserver lines."
        return 0
    fi
    if ! grep -Eq '^[[:space:]]*nameserver[[:space:]]+[^[:space:]]*:[^[:space:]]*([[:space:]]|$)' "$f"; then
        echo "[SKIP] $f: no IPv6 nameserver lines."
        return 0
    fi

    local tmp
    tmp="$(mktemp)"

    local -a ipv4_lines=()
    local -a ipv6_lines=()
    local -a others=()

    local line ip
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*nameserver[[:space:]]+([^[:space:]]+) ]]; then
            ip="${BASH_REMATCH[1]}"
            if is_ipv4 "$ip"; then
                ipv4_lines+=("$line")
            elif is_ipv6 "$ip"; then
                ipv6_lines+=("$line")
            else
                others+=("$line")
            fi
        else
            others+=("$line")
        fi
    done < "$f"

    backup_file "$f"
    {
        printf "%s\n" "${others[@]}" | grep -vE '^[[:space:]]*nameserver[[:space:]]+' || true
        # потом IPv4, потом IPv6
        printf "%s\n" "${ipv4_lines[@]}"
        printf "%s\n" "${ipv6_lines[@]}"
    } > "$tmp"

    sudo cp -f "$tmp" "$f"
    rm -f "$tmp"

    echo "[OK] Reordered nameserver lines in $f (IPv4 first)."
}

fix_dns_order_everywhere() {
    echo "=== Fixing DNS order (IPv4 first, IPv6 after) ==="
    fix_resolv_conf_dns_order
    fix_resolved_conf_dns_order
}

fix_dns_order_everywhere
echo

# ---------- IPv6 state / toggle ----------
check_ipv6_state() {
    if [[ -f /sys/module/ipv6/parameters/disable ]]; then
        local modval
        modval="$(cat /sys/module/ipv6/parameters/disable)"
        if [[ "$modval" == "1" ]]; then
            echo "disabled"
            return
        fi
    fi

    local sysctl_val
    sysctl_val="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "")"
    if [[ "$sysctl_val" == "1" ]]; then
        echo "disabled"
        return
    fi

    if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
        echo "enabled"
        return
    fi

    if [[ "$sysctl_val" == "0" ]]; then
        echo "enabled"
        return
    fi

    echo "unknown"
}

CURRENT_STATE="$(check_ipv6_state)"
echo "Current IPv6 status: ${CURRENT_STATE}"

if [[ "${CURRENT_STATE}" == "enabled" ]]; then
    ACTION="disable"
elif [[ "${CURRENT_STATE}" == "disabled" ]]; then
    ACTION="enable"
else
    echo "Could not determine IPv6 state reliably. Exiting."
    exit 1
fi

# If no tty (non-interactive), do nothing by default.
if ! have_tty; then
    echo "No interactive terminal detected. Exiting without changes."
    exit 0
fi

if ! ask_yes_no "Do you want to ${ACTION} IPv6?"; then
    echo "No changes made."
    exit 0
fi

if [[ "$ACTION" == "disable" ]]; then
    SYSCTL_VAL=1
    GRUB_PARAM="ipv6.disable=1"
else
    SYSCTL_VAL=0
    GRUB_PARAM=""
fi

echo
echo "Applying action: ${ACTION} IPv6 …"

SYSCTL_CONF="/etc/sysctl.d/99-disable_ipv6.conf"
echo "Writing sysctl config to ${SYSCTL_CONF}"
sudo tee "${SYSCTL_CONF}" > /dev/null <<EOF
# Managed by script to ${ACTION} IPv6
net.ipv6.conf.all.disable_ipv6 = ${SYSCTL_VAL}
net.ipv6.conf.default.disable_ipv6 = ${SYSCTL_VAL}
net.ipv6.conf.lo.disable_ipv6 = ${SYSCTL_VAL}
EOF

echo "Applying sysctl settings..."
sudo sysctl --load="${SYSCTL_CONF}" || sudo sysctl -p "${SYSCTL_CONF}"

GRUB_CFG="/etc/default/grub"
echo "Backing up ${GRUB_CFG}"
sudo cp "${GRUB_CFG}" "${GRUB_CFG}.bak_$(date +%Y%m%d%H%M%S)"
echo "Modifying ${GRUB_CFG}"
sudo sed -i 's/ipv6.disable=[01]//g' "${GRUB_CFG}"

if [[ -n "${GRUB_PARAM}" ]]; then
    sudo sed -i -E "s/^(GRUB_CMDLINE_LINUX_DEFAULT=\")([^\"]*)\"/\1\2 ${GRUB_PARAM}\"/" "${GRUB_CFG}"
    sudo sed -i -E "s/^(GRUB_CMDLINE_LINUX=\")([^\"]*)\"/\1\2 ${GRUB_PARAM}\"/" "${GRUB_CFG}"
    echo "Added kernel param '${GRUB_PARAM}'"
else
    echo "Removed kernel param ipv6.disable"
fi

echo "Updating grub..."
sudo update-grub

NEW_STATE="$(check_ipv6_state)"
echo "After changes, IPv6 status is: ${NEW_STATE}"
echo "Note: kernel parameter change requires reboot to fully apply."

if ask_yes_no "Reboot now?"; then
    echo "Rebooting..."
    sudo reboot
else
    echo "Reboot skipped. Please reboot manually later for full effect."
fi

echo
echo "=== Completed: IPv6 has been ${ACTION}d (pending reboot if chosen) ==="
exit 0