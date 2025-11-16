#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Изменения: удалён Shadowsocks; добавлена поддержка flow=vision и shortId;
# добавлен запрос комментария (вместо статичного "Dava"); генерируется QR-код (qrencode).
# Также немного поправлен парсинг ключей x25519.

info(){ echo -e "\n[INFO] $*"; }
err(){ echo -e "\n[ERROR] $*" >&2; }

# install soft
apt update
apt install -y curl openssl qrencode

# install xray (official installer)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

systemctl enable xray
systemctl stop xray || true

# set variables
UUID=$(xray uuid)

# generate x25519 keypair and parse robustly
X25519_OUTPUT=$(xray x25519 2>/dev/null || true)
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | awk -F': ' '/[Pp]rivate/{print $2; exit}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | awk -F': ' '/[Pp]ublic|[Pp]assword/{print $2; exit}')

# fallback if parsing failed (try to re-run)
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  X25519_OUTPUT=$(xray x25519)
  PRIVATE_KEY=$(echo "$X25519_OUTPUT" | awk -F': ' '/[Pp]rivate/{print $2; exit}')
  PUBLIC_KEY=$(echo "$X25519_OUTPUT" | awk -F': ' '/[Pp]ublic|[Pp]assword/{print $2; exit}')
fi

# generate short id (hex)
SHORT_ID=$(openssl rand -hex 4)

# public IP detection
PUBLIC_IP=$(curl -s ipinfo.io/ip || echo "127.0.0.1")

clear

# Ask for server IP (or use detected)
while true; do
  read -rp "Введи внешний IP этого сервера (или нажми Enter, чтобы использовать ${PUBLIC_IP}): " SERVER_IP
  SERVER_IP=${SERVER_IP:-${PUBLIC_IP}}
  # accept 0.0.0.0 as listen all too
  if ip a | grep -q "$SERVER_IP" || [[ "$SERVER_IP" == "0.0.0.0" ]]; then
    break
  else
    echo "Ошибка: адрес не назначен ни на один сетевой интерфейс."
  fi
done

echo

# Ask for VLESS port
while true; do
  read -rp "Введи порт для VLESS (или нажми Enter, чтобы использовать рекомендуемый 443): " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}
  if ! [[ $VLESS_PORT =~ ^[0-9]+$ ]]; then
    echo "Ошибка: необходимо указать число."
    continue
  fi
  if (( VLESS_PORT < 1 || VLESS_PORT > 49151 )); then
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

# Ask for SNI/masking domain (must support TLS1.3)
while true; do
  read -rp "Введи адрес маскировочного домена для Reality (или нажми Enter, чтобы использовать www.yahoo.com): " SNI
  SNI=${SNI:-'www.yahoo.com'}
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "${SNI}:443" -brief 2>&1 || true)
  if echo "$OPENSSL_OUTPUT" | grep -q "TLSv1.3"; then
    break
  else
    echo "Ошибка: указанный сервер должен поддерживать TLSv1.3, попробуй другой."
  fi
done

echo

# Ask for a comment to put into the client link (was static "Dava")
read -rp "Какой комментарий оставить (будет в конце ссылки, по умолчанию 'Dava'): " COMMENT
COMMENT=${COMMENT:-Dava}

# prepare config file (template expected at ./config.json.template)
if [[ ! -f ./config.json.template ]]; then
  err "Файл config.json.template не найден в текущей директории."
  exit 1
fi

cp ./config.json.template /usr/local/etc/xray/config.json

# Replace placeholders in template
# Note: use '|' as sed delimiter to reduce escaping issues.
sed -i "s|SERVER_IP|${SERVER_IP}|g" /usr/local/etc/xray/config.json
sed -i "s|VLESS_PORT|${VLESS_PORT}|g" /usr/local/etc/xray/config.json
sed -i "s|UUID|${UUID}|g" /usr/local/etc/xray/config.json
sed -i "s|PRIVATE_KEY|${PRIVATE_KEY}|g" /usr/local/etc/xray/config.json
sed -i "s|PUBLIC_KEY|${PUBLIC_KEY}|g" /usr/local/etc/xray/config.json
sed -i "s|SHORT_ID|${SHORT_ID}|g" /usr/local/etc/xray/config.json
sed -i "s|SNI|${SNI}|g" /usr/local/etc/xray/config.json

# IMPORTANT:
# - The template must not contain Shadowsocks sections/PLACEHOLDERS anymore (we removed SS).
# - Ensure the template contains placeholders: SERVER_IP, VLESS_PORT, UUID, PRIVATE_KEY, PUBLIC_KEY, SHORT_ID, SNI

# restart xray and check status
systemctl restart xray
sleep 1

echo
if systemctl is-active --quiet xray; then
  echo "Xray статус: active"
else
  echo "Ошибка: служба не запустилась. Попробуй указать другие домены или порты или используй предложенные значения"
  journalctl -u xray --no-pager -n 50 || true
  exit 1
fi

# Build VLESS Reality (vision) URI
# Note: many clients accept query params like pbk (public key), shortid, flow etc. Fragment (#) used for comment/remark.
VLESS_URI="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}/?encryption=none&type=tcp&security=reality&sni=${SNI}&fp=chrome&alpn=h2&flow=xtls-rprx-vision&pbk=${PUBLIC_KEY}&shortid=${SHORT_ID}&packetEncoding=xudp#${COMMENT}"

# Save connection info
echo
echo "========================================"
echo "Строки подключения сохранены в connect.txt и vless_qr.png"
echo

cat > connect.txt <<EOF
VLESS (Reality, flow=vision, shortId):
${VLESS_URI}

Конфигурационный файл: /usr/local/etc/xray/config.json
UUID: ${UUID}
PrivateKey: (скрыт)
PublicKey: ${PUBLIC_KEY}
ShortID: ${SHORT_ID}
SNI: ${SNI}
EOF

# generate QR-code (png) and also print to terminal (UTF8)
if command -v qrencode >/dev/null 2>&1; then
  qrencode -o vless_qr.png "${VLESS_URI}"
  echo -e "\nQR-код сохранён в vless_qr.png (PNG). Также вывод QR в терминал:\n"
  qrencode -t UTF8 "${VLESS_URI}"
else
  echo "qrencode не найден — QR-код не будет создан."
fi

echo
cat connect.txt
echo
echo "========================================"
echo "Используй vpn-клиент Hiddify - https://github.com/hiddify/hiddify-app (по желанию)."
