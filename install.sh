#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\n[INFO] $*"; }
err(){ echo -e "\n[ERROR] $*" >&2; }

# Установка нужных пакетов
apt update
apt install -y curl openssl qrencode || { err "Не удалось установить curl/openssl/qrencode"; exit 1; }

# Установка Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

systemctl enable xray
systemctl stop xray

# Генерация UUID
UUID=$(xray uuid)

# Генерация ключей X25519
X25519_OUTPUT=$(xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | awk '/Private/ {print $2}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | awk '/Public/ {print $2}')

# Генерация корректного shortId (8-16 символов, URL-safe)
SHORT_ID=$(tr -dc 'A-Za-z0-9_- ' < /dev/urandom | head -c12)

PUBLIC_IP=$(curl -s https://ipinfo.io/ip || curl -s https://ifconfig.co || echo "127.0.0.1")
clear

# Выбор IP сервера
while true; do
  read -p "Введи внешний IP сервера (Enter = ${PUBLIC_IP}): " SERVER_IP
  SERVER_IP=${SERVER_IP:-${PUBLIC_IP}}
  if ip a | grep -q "$SERVER_IP"; then
    break
  else
    echo "Ошибка: адрес $SERVER_IP не назначен ни на один сетевой интерфейс."
  fi
done

# Ввод порта VLESS
while true; do
  read -p "Введи порт для VLESS (Enter = 443): " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}
  if ! [[ $VLESS_PORT =~ ^[0-9]+$ ]]; then echo "Нужно число"; continue; fi
  if (( VLESS_PORT < 1 || VLESS_PORT > 49151 )); then echo "Порт вне диапазона"; continue; fi
  if ss -tln | grep -q ":$VLESS_PORT\s"; then echo "Порт занят"; continue; fi
  break
done

# Маскировочный домен
while true; do
  read -p "Введи SNI для Reality (Enter = www.yahoo.com): " SNI
  SNI=${SNI:-'www.yahoo.com'}
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "$SNI":443 -brief 2>&1 || true)
  if echo "$OPENSSL_OUTPUT" | grep -q "Protocol.*TLSv1.3"; then break; else echo "TLSv1.3 отсутствует"; fi
done

# Комментарий клиента
read -p "Комментарий клиента (Enter = Dava): " CLIENT_COMMENT
CLIENT_COMMENT=${CLIENT_COMMENT:-Dava}

# Вариант ручного shortId
read -p "Использовать сгенерированный shortId (${SHORT_ID})? [Y/n]: " USE_SHORT
if [[ "$USE_SHORT" =~ ^[Nn]$ ]]; then
  read -p "Введи shortId (URL-safe, 8-16 символов): " SHORT_ID_CUSTOM
  if [[ -n "$SHORT_ID_CUSTOM" ]]; then
    SHORT_ID=$(echo "$SHORT_ID_CUSTOM" | tr -dc 'A-Za-z0-9_- ' | cut -c1-16)
  fi
fi

# Создание конфигурации Xray
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "info"},
  "inbounds": [{
    "listen": "${SERVER_IP}",
    "port": ${VLESS_PORT},
    "protocol": "vless",
    "tag": "reality-in",
    "settings": {
      "clients": [{
        "id": "${UUID}",
        "flow": "xtls-rprx-vision",
        "email": "${CLIENT_COMMENT}",
        "shortId": "${SHORT_ID}"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "${SNI}:443",
        "xver": 0,
        "serverNames": ["${SNI}"],
        "privateKey": "${PRIVATE_KEY}",
        "minClientVer": "",
        "maxClientVer": "",
        "maxTimeDiff": 0,
        "shortIds": ["${SHORT_ID}"]
      }
    },
    "sniffing": {"enabled": true,"destOverride":["http","tls","quic"]}
  }],
  "outbounds": [{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],
  "routing": {"domainStrategy": "IPIfNonMatch"}
}
EOF

# Перезапуск Xray
systemctl restart xray
sleep 1

if systemctl status xray | grep -q "Active: active (running)"; then
  info "Xray успешно запущен"
else
  err "Ошибка запуска Xray. Проверь логи: journalctl -u xray"
  exit 1
fi

# Генерация VLESS URI
ENC_COMMENT=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "${CLIENT_COMMENT}")
VLESS_URI="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}/?encryption=none&security=reality&type=tcp&fp=chrome&flow=xtls-rprx-vision&alpn=h2&pbk=${PUBLIC_KEY}&packetEncoding=xudp&shortid=${SHORT_ID}#${ENC_COMMENT}"

CONNECT_FILE="connect.txt"
echo -e "VLESS (Reality, xtls-rprx-vision):\n${VLESS_URI}\n\nServer: ${SERVER_IP}:${VLESS_PORT}\nUUID: ${UUID}\nPublicKey: ${PUBLIC_KEY}\nPrivateKey: ${PRIVATE_KEY}\nSNI: ${SNI}\nshortId: ${SHORT_ID}\nКомментарий: ${CLIENT_COMMENT}" > "${CONNECT_FILE}"

# QR-код
QR_PNG="vless_qr.png"
echo -e "\nQR (ASCII) для подключения:"
echo -n "${VLESS_URI}" | qrencode -t UTF8
echo -n "${VLESS_URI}" | qrencode -o "${QR_PNG}"
echo -e "\nQR PNG сохранён в: ${QR_PNG}\nПодключение в файле: ${CONNECT_FILE}"
