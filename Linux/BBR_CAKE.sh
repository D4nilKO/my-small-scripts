#!/bin/bash
set -e

log()          { echo "[INFO] $*"; }
printf_ok()    { echo "[OK] $*"; }
printf_info()  { echo "[INFO] $*"; }
ask_yes_no() { # ask_yes_no "Question (y/n): " "n"
    local prompt="$1" default="${2:-n}" answer
    read -rp "$prompt" answer
    answer="${answer:-$default}"
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

_get_net_status() {
    local cc;    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "n/a")
    local qdisc; qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "n/a")
    if [[ "$qdisc" == "pfifo_fast" ]]; then
        local tc_qdisc; tc_qdisc=$(tc qdisc show 2>/dev/null | grep -Eo 'cake|fq' | head -n1)
        [[ -n "$tc_qdisc" ]] && qdisc="$tc_qdisc"
    fi
    echo "${cc}|${qdisc}"
}

_apply_bbr() {
    log "Запуск настройки сетевых параметров (BBR/CAKE)..."
    local net_status; net_status=$(_get_net_status)
    local current_cc; current_cc=$(echo "$net_status" | cut -d'|' -f1)
    local current_qdisc; current_qdisc=$(echo "$net_status" | cut -d'|' -f2)

    local cake_available
    if modprobe sch_cake &>/dev/null; then
        cake_available="true"
    else
        cake_available="false"
    fi

    echo "----------------------------------------"
    echo "Текущий алгоритм TCP:      $current_cc"
    echo "Текущий планировщик qdisc: $current_qdisc"
    echo "----------------------------------------"

    if [[ ("$current_cc" == "bbr" || "$current_cc" == "bbr2") && "$current_qdisc" == "cake" ]]; then
        printf_ok "BBR/BBR2 и CAKE уже активированы. Дополнительные действия не требуются."
        return 0
    fi

    if ! ask_yes_no "Включить BBR/BBR2 и CAKE? (y/n): " "y"; then
        echo "Операция отменена."
        return 0
    fi

    local preferred_cc="bbr"
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr2"; then
        preferred_cc="bbr2"
    fi

    local preferred_qdisc="fq"
    [[ "$cake_available" == "true" ]] && preferred_qdisc="cake"

    local CONFIG_SYSCTL="/etc/sysctl.d/99-reshala-boost.conf"

    printf_info "Запись параметров в $CONFIG_SYSCTL..."
    cat >"$CONFIG_SYSCTL" <<EOF
# Сетевые параметры производительности
net.core.default_qdisc = ${preferred_qdisc}
net.ipv4.tcp_congestion_control = ${preferred_cc}
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

    printf_info "Применение параметров sysctl..."
    sysctl -p "$CONFIG_SYSCTL" >/dev/null

    printf_ok "Настройка завершена. Активированы: congestion control=${preferred_cc}, qdisc=${preferred_qdisc}."
}

_apply_bbr