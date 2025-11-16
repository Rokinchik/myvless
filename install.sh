#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Xray Reality (VLESS) installer + QR
# Изменения: убран Shadowsocks, добавлен shortId, динамический комментарий, QR-код

info(){ echo -e "\n[INFO] $*"; }
err(){ echo -e "\n[ERROR] $*" >&2; }

# install required packages
apt update
apt install -y curl openssl qrencode || { err "Не удалось установить curl/openssl/qrencode"; exit 1; }

# install xray (official installer)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

systemctl enable xray
systemctl stop xray

# generate ids/keys
UUID=$(xray uuid)
X25519_OUTPUT=$(xray x25519)

# parse keys (expect lines like "Private: ..." and "Public: ...")
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | awk '/Private/ {print $2}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | awk '/Public/ {print $2}')

# shortId (URL-safe base64, no padding) — will be used both in client and realitySettings.shortIds
SHORT_ID=$(openssl rand -base64 12 | tr '+/' '-_' | tr -d '=' | cut -c1-12)

PUBLIC_IP=$(curl -s https://ipinfo.io/ip || curl -s https://ifconfig.co || echo "127.0.0.1")
clear

# Server IP selection (must be assigned to an interface)
while true; do
  read -p "Введи внешний IP этого сервера (или нажми Enter, чтобы использовать ${PUBLIC_IP}): " SERVER_IP
  SERVER_IP=${SERVER_IP:-${PUBLIC_IP}}
  if ip a | grep -q "$SERVER_IP"; then
    break
  else
    echo "Ошибка: адрес $SERVER_IP не назначен ни на один сетевой интерфейс."
  fi
done

echo

# VLESS port
while true; do
  read -p "Введи порт для VLESS (или нажми Enter, чтобы использовать рекомендуемый 443): " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}
  if ! [[ $VLESS_PORT =~ ^[0-9]+$ ]]; then
    echo "Ошибка: необходимо указать число."
    continue
  fi
  if (( VLESS_PORT < 1 || VLESS_PORT > 49151 )); then
    echo "Ошибка: порт должен быть из допустимого диапазона."
    continue
  fi
  if ss -tln | grep -q ":$VLESS_PORT\s"; then
    echo "Ошибка: порт $VLESS_PORT занят, укажи другой."
    continue
  fi
  break
done

echo

# SNI (masking domain) — must support TLS1.3
while true; do
  read -p "Введи адрес маскировочного домена для Reality (или нажми Enter, чтобы использовать www.yahoo.com): " SNI
  SNI=${SNI:-'www.yahoo.com'}
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "$SNI":443 -brief 2>&1 || true)
  if echo "$OPENSSL_OUTPUT" | grep -q "Protocol.*TLSv1.3"; then
    break
  else
    echo "Ошибка: указанный сервер должен поддерживать TLSv1.3, попробуй другой (или проверь доступность)."
  fi
done

echo

# client comment (was Dava) — dynamic per user request
read -p "Введи комментарий для клиента (например 'Dava') или нажми Enter для 'Dava': " CLIENT_COMMENT
CLIENT_COMMENT=${CLIENT_COMMENT:-Dava}

# Allow user to override generated short id (optional)
read -p "Использовать сгенерированный shortId (${SHORT_ID})? [Y/n]: " USE_SHORT
if [[ "$USE_SHORT" =~ ^[Nn]$ ]]; then
  read -p "Введи shortId (не используйте '/' и '+', лучше URL-safe base64): " SHORT_ID_CUSTOM
  if [[ -n "$SHORT_ID_CUSTOM" ]]; then
    SHORT_ID=$(echo "$SHORT_ID_CUSTOM" | tr '+/' '-_' | tr -d '=')
  fi
fi

# write xray config (VLESS Reality only)
mkdir -p /usr/local/etc/xray
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
            "flow": "xtls-rprx-vision",
            "email": "${CLIENT_COMMENT}",
            "shortId": "${SHORT_ID}"
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

# restart and check service
systemctl restart xray
sleep 1

echo
if systemctl status xray | grep -q "Active: active (running)"; then
  echo "Xray успешно запущен."
else
  err "Ошибка: служба xray не запустилась. Проверь /var/log/syslog или journalctl -u xray."
  journalctl -u xray --no-pager | tail -n 50
  exit 1
fi

# build VLESS Reality URI
# Note: некоторые клиенты ожидают разные параметры; этот URI включает публичный ключ и shortId.
# Фрагмент после # — комментарий/метка клиента.
ENC_COMMENT=$(python3 - <<PY
import urllib.parse, sys
print(urllib.parse.quote(sys.argv[1]))
PY
"${CLIENT_COMMENT}")

VLESS_URI="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}/?encryption=none&security=reality&type=tcp&fp=chrome&flow=xtls-rprx-vision&alpn=h2&pbk=${PUBLIC_KEY}&packetEncoding=xudp&shortid=${SHORT_ID}#${ENC_COMMENT}"

# save connection info
CONNECT_FILE="connect.txt"
{
  echo "VLESS (Reality, xtls-rprx-vision):"
  echo "${VLESS_URI}"
  echo
  echo "Параметры:"
  echo "  Server: ${SERVER_IP}:${VLESS_PORT}"
  echo "  UUID: ${UUID}"
  echo "  PublicKey: ${PUBLIC_KEY}"
  echo "  PrivateKey (server): ${PRIVATE_KEY}"
  echo "  SNI: ${SNI}"
  echo "  shortId: ${SHORT_ID}"
  echo "  Комментарий: ${CLIENT_COMMENT}"
} > "${CONNECT_FILE}"

# create QR (PNG) and show ASCII in terminal
QR_PNG="vless_qr.png"
echo -e "\nКод подключения (ASCII QR):"
echo
echo -n "${VLESS_URI}" | qrencode -t UTF8
# also save PNG
echo -n "${VLESS_URI}" | qrencode -o "${QR_PNG}"
echo
echo "QR PNG сохранён в: ${QR_PNG}"
echo "Подключение также записано в файл: ${CONNECT_FILE}"
echo
echo "Полезные данные (содержимое connect.txt):"
echo "========================================"
cat "${CONNECT_FILE}"
echo "========================================"
