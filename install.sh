#!/usr/bin/env bash

# install soft
apt update && apt install -y curl openssl qrencode

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

systemctl enable xray
systemctl stop xray

# set variables
UUID=$(xray uuid)
X25519_OUTPUT=$(xray x25519)

echo "=========================================="
echo "Отладка: Вывод xray x25519:"
echo "$X25519_OUTPUT"
echo "=========================================="

# Правильный парсинг ключей из вывода xray x25519
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep -i 'private key' | awk -F': ' '{print $2}' | tr -d ' \r\n')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep -i 'public key' | awk -F': ' '{print $2}' | tr -d ' \r\n')

# Если не получилось распарсить, пробуем альтернативный метод
if [[ -z "$PRIVATE_KEY" ]]; then
  PRIVATE_KEY=$(echo "$X25519_OUTPUT" | awk 'NR==1 {print $NF}' | tr -d ' \r\n')
fi

if [[ -z "$PUBLIC_KEY" ]]; then
  PUBLIC_KEY=$(echo "$X25519_OUTPUT" | awk 'NR==2 {print $NF}' | tr -d ' \r\n')
fi

# Проверка что ключи не пустые
if [[ -z "$PRIVATE_KEY" ]] || [[ -z "$PUBLIC_KEY" ]]; then
  echo "ОШИБКА: Не удалось извлечь ключи!"
  echo "PRIVATE_KEY='${PRIVATE_KEY}'"
  echo "PUBLIC_KEY='${PUBLIC_KEY}'"
  exit 1
fi

SHORT_ID=$(openssl rand -hex 8)

PUBLIC_IP=$(curl -s ipinfo.io/ip)

clear

# Показываем сгенерированные ключи для проверки
echo "=========================================="
echo "Сгенерированные ключи:"
echo "=========================================="
echo "UUID: ${UUID}"
echo "Private Key: ${PRIVATE_KEY}"
echo "Public Key: ${PUBLIC_KEY}"
echo "Short ID: ${SHORT_ID}"
echo "=========================================="
echo
sleep 3

while true; do
  read -p "Введи внешний IP этого сервера (или нажми Enter, чтобы использовать ${PUBLIC_IP}): " SERVER_IP
  SERVER_IP=${SERVER_IP:-${PUBLIC_IP}}
  if ip a | grep -q "$SERVER_IP"; then
    break
  else
    echo "Ошибка: адрес не назначен ни на один сетевой интерфейс."
  fi
done

echo

while true; do
  read -p "Введи порт для VLESS (или нажми Enter, чтобы использовать рекомендуемый 443): " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}
  if ! [[ $VLESS_PORT =~ ^[0-9]+$ ]]; then
    echo "Ошибка: необходимо указать число."
    continue
  fi
  if (( VLESS_PORT < 1 || VLESS_PORT > 65535 )); then
    echo "Ошибка: порт должен быть из допустимого диапазона."
    continue
  fi
  if ss -tln | grep -q ":$VLESS_PORT "; then
    echo "Ошибка: порт занят, укажи другой."
    continue
  fi
  break
done

echo

while true; do
  read -p "Введи адрес маскировочного домена для Reality (или нажми Enter, чтобы использовать www.yahoo.com): " SNI
  SNI=${SNI:-'www.yahoo.com'}
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "$SNI":443 -brief 2>&1)
  if ! echo "$OPENSSL_OUTPUT" | grep -q "TLSv1.3"; then
    echo "Ошибка: указанный сервер должен поддерживать TLSv1.3, попробуй другой."
    continue
  fi
  break
done

echo

while true; do
  read -p "Введи комментарий для подключения (например, имя сервера): " CONNECTION_NAME
  if [[ -z "$CONNECTION_NAME" ]]; then
    echo "Ошибка: комментарий не может быть пустым."
    continue
  fi
  break
done

# URL encode для комментария
CONNECTION_NAME_ENCODED=$(echo -n "$CONNECTION_NAME" | jq -sRr @uri 2>/dev/null || python3 -c "import urllib.parse; print(urllib.parse.quote('''$CONNECTION_NAME'''))" 2>/dev/null || echo "$CONNECTION_NAME")

# prepare config file
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "${SERVER_IP}",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "tag": "reality-in",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${SNI}:443",
          "xver": 0,
          "serverNames": [
            "${SNI}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch"
  }
}
EOF

echo
echo "Конфигурация создана. Проверка конфига..."
cat /usr/local/etc/xray/config.json | grep -A 2 "privateKey"

# apply settings
systemctl restart xray
sleep 2

echo

if systemctl is-active --quiet xray; then
  echo "✓ Xray запущен успешно!"
  systemctl status xray --no-pager | grep Active
else
  echo "✗ Ошибка: служба не запустилась."
  echo
  echo "Логи ошибок:"
  journalctl -u xray -n 20 --no-pager
  echo
  echo "Попробуй указать другие домены или порты или используй предложенные значения"
  exit 1
fi

# Get connection strings
echo
echo "=========================================="
echo "           ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ        "
echo "=========================================="

# Полная ссылка со всеми параметрами
VLESS_LINK="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none&alpn=h2,http/1.1&packetEncoding=xudp#${CONNECTION_NAME_ENCODED}"

echo
echo "Строка подключения:"
echo "$VLESS_LINK"
echo
echo "$VLESS_LINK" > connect.txt
echo "Сохранено в connect.txt"
echo
echo "=========================================="
echo "           QR-КОД ДЛЯ ПОДКЛЮЧЕНИЯ        "
echo "=========================================="
echo
qrencode -t ANSIUTF8 "$VLESS_LINK"
echo
qrencode -o qr.png "$VLESS_LINK"
echo "QR-код сохранён в файл qr.png"
echo
echo "=========================================="
echo "         ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ           "
echo "=========================================="
echo "Сервер: ${SERVER_IP}:${VLESS_PORT}"
echo "UUID: ${UUID}"
echo "Public Key: ${PUBLIC_KEY}"
echo "Short ID: ${SHORT_ID}"
echo "SNI: ${SNI}"
echo "Flow: xtls-rprx-vision"
echo "ALPN: h2, http/1.1"
echo "Packet Encoding: xudp"
echo "Fingerprint: chrome"
echo "=========================================="
echo
echo "Рекомендуемые клиенты:"
echo "• Hiddify - https://github.com/hiddify/hiddify-app"
echo "• v2rayN (Windows)"
echo "• v2rayNG (Android)"
echo "• Nekobox (Multi-platform)"
echo "=========================================="
