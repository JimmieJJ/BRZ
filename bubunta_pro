#!/bin/bash

# Цвета для оформления меню
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для отображения заголовка
print_header() {
    clear
    echo -e "${BLUE}========================================================${NC}"
    echo -e "${BLUE}      Установка глобального прокси для Ubuntu 24.04     ${NC}"
    echo -e "${BLUE}========================================================${NC}"
    echo
}

# Функция для проверки статуса выполнения команды
check_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} $1"
    else
        echo -e "${RED}[ОШИБКА]${NC} $1"
        exit 1
    fi
}

# Функция для бэкапа файлов
backup_file() {
    if [ -f "$1" ]; then
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp "$1" "$BACKUP_DIR/$(basename $1).$DATE.bak"
        check_status "Создана резервная копия $1"
    fi
}

# Функция для проверки root прав
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Запустите скрипт с правами суперпользователя (sudo).${NC}"
        exit 1
    fi
}

# Функция для сбора информации о прокси
get_proxy_info() {
    print_header
    echo -e "${YELLOW}Для настройки глобального прокси требуется следующая информация:${NC}"
    echo
    
    read -p "IP-адрес прокси-сервера: " PROXY_IP
    while [[ -z "$PROXY_IP" ]]; do
        echo -e "${RED}IP-адрес не может быть пустым!${NC}"
        read -p "IP-адрес прокси-сервера: " PROXY_IP
    done
    
    read -p "Порт прокси-сервера: " PROXY_PORT
    while [[ ! "$PROXY_PORT" =~ ^[0-9]+$ ]]; do
        echo -e "${RED}Порт должен быть числом!${NC}"
        read -p "Порт прокси-сервера: " PROXY_PORT
    done
    
    read -p "Имя пользователя прокси: " PROXY_USER
    while [[ -z "$PROXY_USER" ]]; do
        echo -e "${RED}Имя пользователя не может быть пустым!${NC}"
        read -p "Имя пользователя прокси: " PROXY_USER
    done
    
    read -sp "Пароль прокси: " PROXY_PASS
    echo
    while [[ -z "$PROXY_PASS" ]]; do
        echo -e "${RED}Пароль не может быть пустым!${NC}"
        read -sp "Пароль прокси: " PROXY_PASS
        echo
    done
    
    echo -e "\nВыберите тип прокси:"
    echo "1) SOCKS5 (рекомендуется)"
    echo "2) HTTP"
    read -p "Выбор [1-2]: " proxy_choice
    
    case $proxy_choice in
        1) PROXY_TYPE="socks5" ;;
        2) PROXY_TYPE="http" ;;
        *) PROXY_TYPE="socks5"; echo "Выбран SOCKS5 по умолчанию" ;;
    esac
    
    # Подтверждение информации
    echo
    echo -e "${YELLOW}Проверьте введенные данные:${NC}"
    echo "IP-адрес: $PROXY_IP"
    echo "Порт: $PROXY_PORT"
    echo "Пользователь: $PROXY_USER"
    echo "Тип прокси: $PROXY_TYPE"
    
    read -p "Данные верны? (д/н): " confirm
    if [[ ! "$confirm" =~ ^[дДyY]$ ]]; then
        echo "Ввод данных отменен. Запустите скрипт заново."
        exit 0
    fi
}

# Создаем каталог для бэкапов
BACKUP_DIR="/opt/proxy_backup"
DATE=$(date +%Y%m%d%H%M%S)

# Определение основного сетевого интерфейса
get_default_interface() {
    DEFAULT_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$DEFAULT_INTERFACE" ]; then
        echo "Не удалось определить сетевой интерфейс. Укажите его вручную."
        read -p "Сетевой интерфейс [eth0]: " DEFAULT_INTERFACE
        DEFAULT_INTERFACE=${DEFAULT_INTERFACE:-eth0}
    fi
    echo "Определен сетевой интерфейс: $DEFAULT_INTERFACE"
}

# Функция настройки прокси
setup_proxy() {
    check_root
    get_proxy_info
    get_default_interface
    
    print_header
    echo -e "${YELLOW}===== Начинаем настройку глобального прокси =====${NC}"
    
    # Обновляем список пакетов
    apt update
    check_status "Обновление списка пакетов"
    
    # Устанавливаем необходимые пакеты
    apt install -y proxychains4 dante-client iptables-persistent curl dnsutils net-tools resolvconf
    check_status "Установка необходимых пакетов"
    
    # Бэкап конфигурационных файлов
    backup_file "/etc/proxychains4.conf"
    backup_file "/etc/environment"
    backup_file "/etc/apt/apt.conf.d/proxy.conf"
    backup_file "/etc/docker/daemon.json"
    backup_file "/etc/resolv.conf"
    
    # Настраиваем ProxyChains
    cat > /etc/proxychains4.conf << EOF
# proxychains.conf
strict_chain
quiet_mode
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
$PROXY_TYPE $PROXY_IP $PROXY_PORT $PROXY_USER $PROXY_PASS
EOF
    check_status "Настройка ProxyChains"
    
    # Настройка глобальных переменных окружения
    cat > /etc/environment << EOF
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
http_proxy="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
https_proxy="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
ftp_proxy="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
no_proxy="localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
HTTP_PROXY="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
HTTPS_PROXY="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
FTP_PROXY="http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
NO_PROXY="localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EOF
    check_status "Настройка глобальных переменных окружения"
    
    # Настройка прокси для APT
    mkdir -p /etc/apt/apt.conf.d/
    cat > /etc/apt/apt.conf.d/proxy.conf << EOF
Acquire::http::Proxy "http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/";
Acquire::https::Proxy "http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/";
Acquire::ftp::Proxy "http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/";
EOF
    check_status "Настройка прокси для APT"
    
    # Настройка прокси для wget
    mkdir -p /etc/wgetrc.d/ || true
    cat > /etc/wgetrc << EOF
https_proxy = http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/
http_proxy = http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/
ftp_proxy = http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/
use_proxy = on
EOF
    check_status "Настройка прокси для wget"
    
    # Настройка Docker для использования прокси
    if command -v docker &>/dev/null; then
        mkdir -p /etc/systemd/system/docker.service.d/
        cat > /etc/systemd/system/docker.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
Environment="HTTPS_PROXY=http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/"
Environment="NO_PROXY=localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EOF
        check_status "Настройка прокси для Docker service"
        
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << EOF
{
  "proxies": {
    "default": {
      "httpProxy": "http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/",
      "httpsProxy": "http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/",
      "noProxy": "localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    }
  }
}
EOF
        check_status "Настройка прокси для Docker daemon"
    else
        echo "Docker не установлен, пропускаем настройку Docker"
    fi

    # Настройка прокси для Git
    git config --system http.proxy http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/ || true
    git config --system https.proxy http://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT/ || true
    
    # Настройка torsocks для альтернативного метода проксирования
    if ! command -v torsocks &>/dev/null; then
        apt install -y torsocks
        check_status "Установка torsocks"
    fi
    
    backup_file "/etc/tor/torsocks.conf"
    cat > /etc/tor/torsocks.conf << EOF
TorAddress $PROXY_IP
TorPort $PROXY_PORT
OnionAddrRange 127.0.0.1/8
SOCKS5Username $PROXY_USER
SOCKS5Password $PROXY_PASS
EOF
    check_status "Настройка torsocks"
    
    # Настройка DNS через прокси
    if [ "$PROXY_TYPE" = "socks5" ]; then
        # Для SOCKS5 настраиваем переброс DNS через прокси
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        
        # Устанавливаем dnscrypt-proxy для DNS через SOCKS
        apt install -y dnscrypt-proxy
        check_status "Установка dnscrypt-proxy"
        
        backup_file "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
        cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << EOF
listen_addresses = ['127.0.0.1:53']
server_names = ['cloudflare']
proxy = 'socks5://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT'
EOF
        systemctl restart dnscrypt-proxy
        check_status "Настройка dnscrypt-proxy"
    fi
    
    # Настраиваем правила iptables для перенаправления трафика
    # Сохраняем текущие правила
    iptables-save > "$BACKUP_DIR/iptables.$DATE.bak"
    ip6tables-save > "$BACKUP_DIR/ip6tables.$DATE.bak"
    
    # Создаем пользователя для работы прокси
    if ! id -u proxy_user &>/dev/null; then
        useradd -r -s /bin/false proxy_user
        check_status "Создание пользователя proxy_user"
    fi
    
    # Очищаем текущие правила
    iptables -t nat -F
    
    # Настраиваем перенаправление трафика (кроме локального и прокси)
    iptables -t nat -A OUTPUT -m owner --uid-owner proxy_user -j RETURN
    iptables -t nat -A OUTPUT -d $PROXY_IP -j RETURN
    iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN
    
    # Использовать TransparentProxy через ProxyChains
    # Установка redsocks для прозрачного проксирования через SOCKS5
    apt install -y redsocks
    check_status "Установка redsocks"
    
    backup_file "/etc/redsocks.conf"
    cat > /etc/redsocks.conf << EOF
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    
    ip = $PROXY_IP;
    port = $PROXY_PORT;
    type = $([ "$PROXY_TYPE" = "socks5" ] && echo "socks5" || echo "http-connect");
    login = "$PROXY_USER";
    password = "$PROXY_PASS";
}
EOF
    systemctl restart redsocks
    check_status "Настройка и запуск redsocks"
    
    # Настройка перенаправления через redsocks
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12345
    
    # Сохраняем правила iptables для автозагрузки
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    check_status "Настройка и сохранение правил iptables"
    
    # Создаем скрипт для запуска приложений через proxychains
    cat > /usr/local/bin/proxify << EOF
#!/bin/bash
proxychains4 -q "\$@"
EOF
    chmod +x /usr/local/bin/proxify
    check_status "Создан скрипт 'proxify' для запуска приложений через прокси"
    
    # Создаем альтернативный скрипт для запуска через torsocks
    cat > /usr/local/bin/proxy-tor << EOF
#!/bin/bash
torsocks "\$@"
EOF
    chmod +x /usr/local/bin/proxy-tor
    check_status "Создан скрипт 'proxy-tor' для запуска приложений через torsocks"

    echo -e "${YELLOW}===== Проверка настройки прокси =====${NC}"
    
    # Проверяем текущий IP с помощью нескольких сервисов
    echo "Проверка IP..."
    echo "Через curl:"
    curl -s https://ifconfig.me || echo "Не удалось определить IP через ifconfig.me"
    echo "Через proxychains curl:"
    proxychains4 -q curl -s https://ifconfig.me || echo "Не удалось определить IP через proxychains с ifconfig.me"
    
    echo "Альтернативная проверка:"
    curl -s https://api.ipify.org || echo "Не удалось определить IP через ipify.org"
    echo "Через proxychains:"
    proxychains4 -q curl -s https://api.ipify.org || echo "Не удалось определить IP через proxychains с ipify.org"
    
    echo "DNS проверка:"
    proxychains4 -q dig +short google.com || echo "DNS проверка через dig не удалась"
    proxychains4 -q nslookup google.com || echo "DNS проверка через nslookup не удалась"
    
    echo ""
    echo -e "${GREEN}===== Настройка прокси завершена =====${NC}"
    echo -e "${YELLOW}Теперь весь трафик должен идти через прокси $PROXY_IP:$PROXY_PORT${NC}"
    echo -e "${YELLOW}Для запуска программ через прокси используйте: ${GREEN}proxify program_name${NC}"
    echo -e "${YELLOW}Для запуска через альтернативный метод: ${GREEN}proxy-tor program_name${NC}"
    echo -e "${YELLOW}Для проверки настроек выполните: ${GREEN}$0 check${NC}"
    echo -e "${YELLOW}Для отката изменений выполните: ${GREEN}$0 restore${NC}"
    
    # Рекомендация перезагрузить систему
    echo
    echo -e "${YELLOW}Рекомендуется перезагрузить систему, чтобы все изменения вступили в силу.${NC}"
    read -p "Перезагрузить систему сейчас? (д/н): " reboot_now
    if [[ "$reboot_now" =~ ^[дДyY]$ ]]; then
        echo "Перезагрузка системы..."
        sudo reboot
    fi
}

# Функция восстановления исходной конфигурации
restore_config() {
    check_root
    
    print_header
    echo -e "${YELLOW}===== Восстановление исходной конфигурации =====${NC}"
    
    # Останавливаем сервисы
    systemctl stop redsocks || true
    systemctl stop dnscrypt-proxy || true
    
    # Восстанавливаем файлы из бэкапа
    for file in /etc/proxychains4.conf /etc/environment /etc/apt/apt.conf.d/proxy.conf /etc/docker/daemon.json /etc/resolv.conf /etc/tor/torsocks.conf /etc/dnscrypt-proxy/dnscrypt-proxy.toml /etc/redsocks.conf; do
        latest_backup=$(ls -t "$BACKUP_DIR/$(basename $file)".*.bak 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            sudo cp "$latest_backup" "$file"
            check_status "Восстановлен файл $file"
        else
            sudo rm -f "$file"
            check_status "Удален файл $file (бэкап не найден)"
        fi
    done
    
    # Сбрасываем настройки Git
    git config --system --unset http.proxy || true
    git config --system --unset https.proxy || true
    
    # Восстановление iptables
    latest_iptables=$(ls -t "$BACKUP_DIR/iptables".*.bak 2>/dev/null | head -1)
    if [ -n "$latest_iptables" ]; then
        iptables-restore < "$latest_iptables"
        iptables-save > /etc/iptables/rules.v4
        check_status "Восстановлены правила iptables"
    else
        iptables -F
        iptables -t nat -F
        iptables-save > /etc/iptables/rules.v4
        check_status "Очищены правила iptables (бэкап не найден)"
    fi
    
    latest_ip6tables=$(ls -t "$BACKUP_DIR/ip6tables".*.bak 2>/dev/null | head -1)
    if [ -n "$latest_ip6tables" ]; then
        ip6tables-restore < "$latest_ip6tables"
        ip6tables-save > /etc/iptables/rules.v6
        check_status "Восстановлены правила ip6tables"
    else
        ip6tables -F
        ip6tables -t nat -F
        ip6tables-save > /etc/iptables/rules.v6
        check_status "Очищены правила ip6tables (бэкап не найден)"
    fi
    
    # Удаляем файлы настройки Docker
    rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
    
    # Удаляем скрипты
    rm -f /usr/local/bin/proxify
    rm -f /usr/local/bin/proxy-tor
    
    # Перезапускаем службы
    systemctl daemon-reload
    if systemctl is-active --quiet docker; then
        systemctl restart docker
    fi
    
    echo -e "${GREEN}===== Исходная конфигурация восстановлена =====${NC}"
    
    # Рекомендация перезагрузить систему
    echo
    echo -e "${YELLOW}Рекомендуется перезагрузить систему, чтобы все изменения вступили в силу.${NC}"
    read -p "Перезагрузить систему сейчас? (д/н): " reboot_now
    if [[ "$reboot_now" =~ ^[дДyY]$ ]]; then
        echo "Перезагрузка системы..."
        sudo reboot
    fi
}

# Функция проверки настроек прокси
check_proxy() {
    check_root
    
    print_header
    echo -e "${YELLOW}===== Проверка настройки прокси =====${NC}"
    
    # Проверка IP с помощью нескольких сервисов
    echo -e "${BLUE}Текущий IP (curl):${NC}"
    curl -s https://ifconfig.me || echo "Не удалось определить IP через ifconfig.me"
    
    echo -e "\n${BLUE}Текущий IP (альтернативный сервис):${NC}"
    curl -s https://api.ipify.org || echo "Не удалось определить IP через ipify.org"
    
    echo -e "\n${BLUE}IP через proxychains:${NC}"
    proxychains4 -q curl -s https://ifconfig.me || echo "Не удалось определить IP через proxychains с ifconfig.me"
    
    echo -e "\n${BLUE}DNS проверка:${NC}"
    echo "- Через dig:"
    proxychains4 -q dig +short google.com || echo "DNS проверка через dig не удалась"
    
    echo "- Через nslookup:"
    proxychains4 -q nslookup google.com || echo "DNS проверка через nslookup не удалась"
    
    # Проверка утечек WebRTC
    echo -e "\n${BLUE}Проверка утечек WebRTC (требуется браузер):${NC}"
    echo "Откройте https://browserleaks.com/webrtc в браузере"
    
    # Проверка переменных окружения
    echo -e "\n${BLUE}Проверка переменных окружения:${NC}"
    grep -E 'http_proxy|https_proxy' /etc/environment
    
    # Проверка настроек Docker
    if [ -f "/etc/systemd/system/docker.service.d/http-proxy.conf" ] && command -v docker &>/dev/null; then
        echo -e "\n${BLUE}Настройки прокси Docker:${NC}"
        cat /etc/systemd/system/docker.service.d/http-proxy.conf
        
        echo -e "\n${BLUE}Тест Docker с прокси:${NC}"
        docker info 2>/dev/null | grep -i proxy || echo "Прокси не настроен в Docker"
    else
        echo -e "\n${YELLOW}Docker не установлен или файл настроек прокси Docker не найден${NC}"
    fi
    
    # Проверка работы redsocks
    echo -e "\n${BLUE}Статус сервиса redsocks:${NC}"
    if systemctl is-active --quiet redsocks; then
        echo -e "${GREEN}Сервис redsocks активен${NC}"
    else
        echo -e "${RED}Сервис redsocks не запущен!${NC}"
    fi
    
    # Проверка правил iptables
    echo -e "\n${BLUE}Правила перенаправления iptables:${NC}"
    iptables -t nat -L OUTPUT -n -v | grep -i redirect
    
    echo
    echo -e "${YELLOW}===== Проверка завершена =====${NC}"
    echo -e "${YELLOW}Для запуска программ через прокси используйте: ${GREEN}proxify program_name${NC}"
    echo -e "${YELLOW}Для запуска через альтернативный метод: ${GREEN}proxy-tor program_name${NC}"
}

# Функция для отображения справки
show_help() {
    print_header
    echo -e "${YELLOW}Использование:${NC}"
    echo -e "  ${GREEN}sudo $0${NC} без параметров - запуск интерактивного меню"
    echo -e "  ${GREEN}sudo $0 setup${NC}   - настроить глобальный прокси с интерактивным вводом"
    echo -e "  ${GREEN}sudo $0 restore${NC} - восстановить исходную конфигурацию"
    echo -e "  ${GREEN}sudo $0 check${NC}   - проверить настройки прокси"
    echo -e "  ${GREEN}sudo $0 help${NC}    - показать эту справку"
    echo
    echo -e "${YELLOW}После настройки прокси:${NC}"
    echo -e "- Для запуска программ через прокси используйте: ${GREEN}proxify program_name${NC}"
    echo -e "- Для запуска через альтернативный метод: ${GREEN}proxy-tor program_name${NC}"
    echo -e "- В случае возникновения проблем попробуйте перезагрузить систему"
    echo
}

# Функция отображения меню
show_menu() {
    while true; do
        print_header
        echo -e "${YELLOW}Выберите действие:${NC}"
        echo "1) Настроить глобальный прокси"
        echo "2) Восстановить исходную конфигурацию"
        echo "3) Проверить настройки прокси"
        echo "4) Показать справку"
        echo "0) Выход"
        echo
        read -p "Ваш выбор [0-4]: " choice
        
        case $choice in
            1) setup_proxy; break ;;
            2) restore_config; break ;;
            3) check_proxy; break ;;
            4) show_help; read -p "Нажмите Enter для продолжения..." ;;
            0) echo "Выход из программы."; exit 0 ;;
            *) echo -e "${RED}Неверный выбор. Попробуйте снова.${NC}" 
               read -p "Нажмите Enter для продолжения..." ;;
        esac
    done
}

# Обработка аргументов командной строки
case "$1" in
    setup)
        setup_proxy
        ;;
    restore)
        restore_config
        ;;
    check)
        check_proxy
        ;;
    help)
        show_help
        ;;
    *)
        show_menu
        ;;
esac

exit 0
