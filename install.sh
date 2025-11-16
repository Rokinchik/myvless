#!/usr/bin/env bash

# install soft
apt update && apt install -y curl openssl qrencode

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

systemctl enable xray
systemctl stop xray

# set variables
UUID=$(xray uuid)
X25519_OUTPUT=$(xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep 'Private' | awk '{print $3}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep 'Public' | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)

PUBLIC_IP=$(curl -s ipinfo.io/ip)

clear

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

# apply settings
systemctl restart xray
sleep 2

echo

if systemctl status xray | grep -q active; then
  echo "Xray статус:"
  systemctl status xray | grep Active
else
  echo "Ошибка: служба не запустилась. Попробуй указать другие домены или порты или используй предложенные значения"
  exit 1
fi

# Get connection strings
echo
echo "========================================"

VLESS_LINK="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${CONNECTION_NAME}"

echo "Строка подключения сохранена в connect.txt:"
echo
echo "$VLESS_LINK" | tee connect.txt
echo
echo "========================================"
echo "QR-код для подключения:"
echo
qrencode -t ANSIUTF8 "$VLESS_LINK"
echo
echo "QR-код также сохранён в файл qr.png"
qrencode -o qr.png "$VLESS_LINK"
echo
echo "========================================"
echo "Используй vpn-клиент Hiddify - https://github.com/hiddify/hiddify-app"
echo "Или любой клиент с поддержкой VLESS Reality (v2rayN, v2rayNG, Nekobox)"
echo
echo "Параметры подключения:"
echo "UUID: ${UUID}"
echo "Public Key: ${PUBLIC_KEY}"
echo "Short ID: ${SHORT_ID}"
echo "SNI: ${SNI}"
