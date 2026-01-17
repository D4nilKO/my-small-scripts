#!/bin/bash

set -e

LANG_CHOICE=""
MSG_LANG=""
declare -A MSG

select_language() {
    echo "Select language / Выберите язык:"
    echo "1) English"
    echo "2) Русский"
    read -rp "> " LANG_CHOICE

    case "$LANG_CHOICE" in
        1) MSG_LANG="en" ;;
        2) MSG_LANG="ru" ;;
        *) MSG_LANG="en" ;;
    esac

    if [[ "$MSG_LANG" == "ru" ]]; then
        MSG[select_done]="Выбран язык: Русский"
        MSG[start]="Запуск настройки сетевых параметров (BBR/CAKE)..."
        MSG[current_cc]="Текущий алгоритм TCP:"
        MSG[current_qdisc]="Текущий планировщик qdisc:"
        MSG[already_ok]="BBR/BBR2 и CAKE уже активированы. Дополнительные действия не требуются."
        MSG[ask_enable]="Включить BBR/BBR2 и CAKE? (y/n): "
        MSG[canceled]="Операция отменена."
        MSG[write_sysctl]="Запись параметров в"
        MSG[apply_sysctl]="Применение параметров sysctl..."
        MSG[done]="Настройка завершена. Активированы:"
    else
        MSG[select_done]="Selected language: English"
        MSG[start]="Starting network tuning (BBR/CAKE)..."
        MSG[current_cc]="Current TCP congestion control:"
        MSG[current_qdisc]="Current qdisc scheduler:"
        MSG[already_ok]="BBR/BBR2 and CAKE are already enabled. No action required."
        MSG[ask_enable]="Enable BBR/BBR2 and CAKE? (y/n): "
        MSG[canceled]="Operation cancelled."
        MSG[write_sysctl]="Writing sysctl parameters to"
        MSG[apply_sysctl]="Applying sysctl parameters..."
        MSG[done]="Configuration complete. Enabled:"
    fi

    echo "[INFO] ${MSG[select_done]}"
}

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
    log "${MSG[start]}"
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
    echo "${MSG[current_cc]}      $current_cc"
    echo "${MSG[current_qdisc]} $current_qdisc"
    echo "----------------------------------------"

    if [[ ("$current_cc" == "bbr" || "$current_cc" == "bbr2") && "$current_qdisc" == "cake" ]]; then
        printf_ok "${MSG[already_ok]}"
        return 0
    fi

    if ! ask_yes_no "${MSG[ask_enable]}" "y"; then
        echo "${MSG[canceled]}"
        return 0
    fi

    local preferred_cc="bbr"
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr2"; then
        preferred_cc="bbr2"
    fi

    local preferred_qdisc="fq"
    [[ "$cake_available" == "true" ]] && preferred_qdisc="cake"

    local CONFIG_SYSCTL="/etc/sysctl.d/99-reshala-boost.conf"

    printf_info "${MSG[write_sysctl]} $CONFIG_SYSCTL..."
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

    printf_info "${MSG[apply_sysctl]}"
    sysctl -p "$CONFIG_SYSCTL" >/dev/null

    printf_ok "${MSG[done]} congestion control=${preferred_cc}, qdisc=${preferred_qdisc}."
}

select_language
_apply_bbr