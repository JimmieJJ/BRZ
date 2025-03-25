#!/bin/bash

# Функция для проверки корректности IP-адреса
validate_ip() {
    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Функция для проверки корректности номера порта
validate_port() {
    if [[ $1 =~ ^[0-9]+$ ]] && [ $1 -ge 1 ] && [ $1 -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# Проверка прав суперпользователя
if [ "$EUID" -ne 0 ]; then
    echo "Запустите скрипт с правами суперпользователя (sudo)."
    exit 1
fi

# Запрос данных у пользователя
while true; do
    read -p "Введите IP-адрес прокси: " PROXY_IP
    if validate_ip "$PROXY_IP"; then
        break
    else
        echo "Некорректный IP-адрес. Попробуйте снова."
    fi
done

while true; do
    read -p "Введите порт прокси: " PROXY_PORT
    if validate_port "$PROXY_PORT"; then
        break
    else
        echo "Некорректный номер порта. Попробуйте снова."
    fi
done

read -p "Введите логин для прокси: " PROXY_USER
read -p "Введите пароль для прокси: " PROXY_PASS

while true; do
    read -p "Выберите тип прокси (socks5/http) [по умолчанию socks5]: " PROXY_TYPE
    PROXY_TYPE=${PROXY_TYPE:-socks5}
    if [[ "$PROXY_TYPE" == "socks5" || "$PROXY_TYPE" == "http" ]]; then
        break
    else
        echo "Некорректный тип прокси. Введите socks5 или http."
    fi
done

# Создаем полный скрипт с подставленными параметрами
cat > /usr/local/bin/setup_proxy.sh << 'EOORIGINAL'
#!/bin/bash

# Скрипт настройки глобального прокси для Ubuntu 24.04
# Перенаправляет весь трафик через указанный прокси
# Настройки прокси (измените на свои)
PROXY_IP="$PROXY_IP"
PROXY_PORT="$PROXY_PORT"
PROXY_USER="$PROXY_USER"
PROXY_PASS="$PROXY_PASS"
PROXY_TYPE="$PROXY_TYPE" # или http

# Создаем каталог для бэкапов
BACKUP_DIR="/opt/proxy_backup"
DATE=$(date +%Y%m%d%H%M%S)

# Функция для проверки статуса выполнения команды
check_status() {
    if [ $? -eq 0 ]; then
        echo -e "\e[32m[OK]\e[0m $1"
    else
        echo -e "\e[31m[ОШИБКА]\e[0m $1"
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

# Проверка root прав
if [ "$EUID" -ne 0 ]; then
    echo "Запустите скрипт с правами суперпользователя (sudo)."
    exit 1
fi

# Определение основного сетевого интерфейса
DEFAULT_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
if [ -z "$DEFAULT_INTERFACE" ]; then
    echo "Не удалось определить сетевой интерфейс. Укажите его вручную в скрипте."
    DEFAULT_INTERFACE="eth0"  # Значение по умолчанию
fi
echo "Определен сетевой интерфейс: $DEFAULT_INTERFACE"

case "$1" in
    setup)
        echo "===== Начинаем настройку глобального прокси ====="
        
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

        echo "===== Проверка настройки прокси ====="
        
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
        echo "===== Настройка прокси завершена ====="
        echo "Теперь весь трафик должен идти через прокси $PROXY_IP:$PROXY_PORT"
        echo "Для запуска программ через прокси используйте: proxify program_name"
        echo "Для запуска через альтернативный метод: proxy-tor program_name"
        echo "Для отката изменений выполните: $0 restore"
        ;;
    
    restore)
        echo "===== Восстановление исходной конфигурации ====="
        
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
        
        echo "===== Исходная конфигурация восстановлена ====="
        ;;
    
    check)
        echo "===== Проверка настройки прокси ====="
        
        # Проверка IP с помощью нескольких сервисов
        echo "Текущий IP (curl):"
        curl -s https://ifconfig.me || echo "Не удалось определить IP через ifconfig.me"
        
        echo "Текущий IP (альтернативный сервис):"
        curl -s https://api.ipify.org || echo "Не удалось определить IP через ipify.org"
        
        echo "IP через proxychains:"
        proxychains4 -q curl -s https://ifconfig.me || echo "Не удалось определить IP через proxychains с ifconfig.me"
        
        echo "DNS проверка:"
        echo "- Через dig:"
        proxychains4 -q dig +short google.com || echo "DNS проверка через dig не удалась"
        
        echo "- Через nslookup:"
        proxychains4 -q nslookup google.com || echo "DNS проверка через nslookup не удалась"
        
        # Проверка утечек WebRTC
        echo "Проверка утечек WebRTC (требуется браузер):"
        echo "Откройте https://browserleaks.com/webrtc в браузере"
        
        # Проверка переменных окружения
        echo "Проверка переменных окружения:"
        grep -E 'http_proxy|https_proxy' /etc/environment
        
        # Проверка настроек Docker
        if [ -f "/etc/systemd/system/docker.service.d/http-proxy.conf" ] && command -v docker &>/dev/null; then
            echo "Настройки прокси Docker:"
            cat /etc/systemd/system/docker.service.d/http-proxy.conf
            
            echo "Тест Docker с прокси:"
            docker info 2>/dev/null | grep -i proxy || echo "Прокси не настроен в Docker"
        else
            echo "Docker не установлен или файл настроек прокси Docker не найден"
        fi
        
        # Проверка работы redsocks
        if systemctl is-active --quiet redsocks; then
            echo "Сервис redsocks активен"
        else
            echo "Сервис redsocks не запущен!"
        fi
        
        # Проверка правил iptables
        echo "Правила перенаправления iptables:"
        iptables -t nat -L OUTPUT -n -v | grep -i redirect
        ;;
    
    *)
        echo "Использование:"
        echo "  $0 setup   - Настроить глобальный прокси"
        echo "  $0 restore - Восстановить исходную конфигурацию"
        echo "  $0 check   - Проверить настройки прокси"
        ;;
esac

exit 0
EOORIGINAL

# Делаем файл исполняемым
chmod +x /usr/local/bin/setup_proxy.sh

# Выполняем настройку прокси
/usr/local/bin/setup_proxy.sh setup

# Проверяем настройки
/usr/local/bin/setup_proxy.sh check

# Предлагаем перезагрузку
read -p "Рекомендуется перезагрузить систему. Выполнить перезагрузку? (да/нет): " reboot_choice
if [[ "$reboot_choice" =~ ^[Дд][аА]$ ]]; then
    echo "Выполняется перезагрузка..."
    reboot
else
    echo "Перезагрузка отменена. Не забудьте перезагрузить систему позже."
fi
