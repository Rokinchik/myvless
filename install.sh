#!/usr/bin/env bash
# Установка ПО
apt update && apt install -y curl openssl jq qrencode # Добавил qrencode для генерации QR
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray
systemctl stop xray
# Генерация переменных
UUID=$(xray uuid)
if [[ -z "$UUID" ]]; then
  echo "Ошибка: Не удалось сгенерировать UUID!"
  exit 1
fi
X25519_OUTPUT=$(xray x25519)
# Парсинг для новой версии (v25+): PrivateKey, Password (pub), Hash32
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | sed -n 's/.*PrivateKey:[[:space:]]*//p' | head -n1 | tr -d ' \n\r')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | sed -n 's/.*Password:[[:space:]]*//p' | head -n1 | tr -d ' \n\r')
HASH32=$(echo "$X25519_OUTPUT" | sed -n 's/.*Hash32:[[:space:]]*//p' | head -n1 | tr -d ' \n\r')
# Fallback для старого формата (если нужно)
if [[ -z "$PRIVATE_KEY" ]]; then
  PRIVATE_KEY=$(echo "$X25519_OUTPUT" | sed -n 's/.*Private key:[[:space:]]*//p' | head -n1 | tr -d ' \n\r')
fi
if [[ -z "$PUBLIC_KEY" ]]; then
  PUBLIC_KEY=$(echo "$X25519_OUTPUT" | sed -n 's/.*Public key:[[:space:]]*//p' | head -n1 | tr -d ' \n\r')
fi
# Проверка ключей
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "Ошибка: Не удалось сгенерировать ключи! Вывод xray x25519:"
  echo "$X25519_OUTPUT"
  exit 1
fi
echo "Сгенерированы ключи: Private=${PRIVATE_KEY:0:10}... Public=${PUBLIC_KEY:0:10}... (Hash32=${HASH32:0:10}...)"
SHORT_ID=$(openssl rand -hex 4) # Random hex, или используй ${HASH32:0:8} если хочешь
PUBLIC_IP=$(curl -s ipinfo.io/ip)
clear
# Ввод IP (только для URL, не для listen)
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
# Ввод порта VLESS
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
  if ss -tln | grep -q ":$VLESS_PORT "; then
    echo "Ошибка: порт занят, укажи другой."
    continue
  fi
  break
done
echo
# Ввод SNI
while true; do
  read -p "Введи адрес маскировочного домена для Reality (или нажми Enter, чтобы использовать www.yahoo.com): " SNI
  SNI=${SNI:-'www.yahoo.com'}
  echo "Проверяю TLSv1.3 для $SNI..."
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "$SNI":443 -brief 2>&1)
  if ! echo "$OPENSSL_OUTPUT" | grep -q "TLSv1.3"; then
    echo "Ошибка: указанный сервер должен поддерживать TLSv1.3."
    echo "Вывод openssl: $OPENSSL_OUTPUT"
    echo "Попробуй другой домен (например, www.google.com)."
    continue
  fi
  break
done
echo
# Подготовка config.json
cat << EOF > /usr/local/etc/xray/config.json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": null,
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
            "${SHORT_ID}",
            "" // Добавил пустой для совместимости
          ]
        },
        "tcpSettings": {
          "header": {
            "type": "http"
          }
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
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIP"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "block",
        "domain": [
          "geosite:category-ads-all"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "udp,tcp"
      }
    ]
  }
}
EOF
# Применение настроек
systemctl restart xray
sleep 2
echo
if systemctl status xray | grep -q active; then
  echo "Xray статус: active (running)"
  echo "Успех! Конфиг применён."
else
  echo "Ошибка: служба не запустилась."
  echo "Последние логи Xray (journalctl):"
  journalctl -u xray -n 10 --no-pager
  echo "Попробуй указать другие домены или порты, или используй предложенные значения."
  echo "Также проверь firewall: ufw allow ${VLESS_PORT}/tcp или iptables -A INPUT -p tcp --dport ${VLESS_PORT} -j ACCEPT"
  exit 1
fi
# Ввод комментария
read -p "Введи комментарий для конфигурации (или нажми Enter, чтобы использовать Dava): " COMMENT
COMMENT=${COMMENT:-Dava}
# Генерация строки подключения
VLESS_URL="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&type=tcp&sni=${SNI}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&packetEncoding=xudp#${COMMENT}"
echo
echo "========================================"
echo "Строка подключения VLESS сохранена в connect.txt:"
echo
echo "VLESS:" > connect.txt
echo "$VLESS_URL" >> connect.txt
cat connect.txt
echo
echo "QR-код для подключения (отсканируй в Hiddify/v2rayNG):"
qrencode -t ansi "$VLESS_URL"
echo
echo "========================================"
echo "ShortId: ${SHORT_ID} (добавлен для усиления маскировки)"
echo "Private Key в config: ${PRIVATE_KEY:0:10}... (проверь в /usr/local/etc/xray/config.json)"
echo "Public Key для клиента: ${PUBLIC_KEY}"
echo "Hash32 (опционально): ${HASH32}"
echo "Используй vpn-клиент Hiddify - https://github.com/hiddify/hiddify-app или v2rayNG для Android/iOS."
echo "Для мониторинга: journalctl -u xray -f"
