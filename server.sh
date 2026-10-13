#!/usr/bin/env bash
set -e

# Default parameters
PORT=8443
SOCKS_PORT=10808
HTTP_PORT=10809
SNI="api.github.com"
WS_PATH="/api/v3/user/repos"
UUID="e7b99c43-4dc9-408a-b852-7b5638a16db8"
XRAY_VER="v26.3.27"
SERVICE_NAME="g2reverse"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

ACTION="install"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    start|stop|restart|status|logs|uninstall)
      ACTION="$1"; shift ;;
    -p|--port)
      PORT="$2"; shift 2 ;;
    -s|--socks)
      SOCKS_PORT="$2"; shift 2 ;;
    --http)
      HTTP_PORT="$2"; shift 2 ;;
    --sni)
      SNI="$2"; shift 2 ;;
    --path)
      WS_PATH="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: ./server.sh [command] [options]"
      echo ""
      echo "Commands:"
      echo "  (default)               Setup and start systemd service"
      echo "  status                  Show service status and connection info"
      echo "  logs                    View live logs (journalctl)"
      echo "  restart                 Restart systemd service"
      echo "  stop                    Stop systemd service"
      echo "  start                   Start systemd service"
      echo "  uninstall               Remove systemd service"
      echo ""
      echo "Options:"
      echo "  -p, --port <port>       Portal forwarded port (default: 8443)"
      echo "  -s, --socks <port>      Local SOCKS5 proxy port (default: 10808)"
      echo "      --http <port>       Local HTTP proxy port (default: 10809)"
      echo "      --sni <domain>      Camouflage SNI / Host (default: api.github.com)"
      echo "      --path <path>       WebSocket path (default: /api/v3/user/repos)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Sub-command handlers
case "$ACTION" in
  status)
    sudo systemctl status "$SERVICE_NAME" --no-pager || true
    echo ""
    if [[ -f "$SCRIPT_DIR/cert.pem" ]]; then
      CERT_SHA256=$(openssl x509 -in "$SCRIPT_DIR/cert.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
      PUB_IP=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me || echo "<YOUR_SERVER_IP>")
      echo "---------------- GitHub Actions Parameters ----------------"
      echo "Public IP:          $PUB_IP"
      echo "Certificate SHA256: $CERT_SHA256"
      echo "-----------------------------------------------------------"
    fi
    exit 0
    ;;
  logs)
    sudo journalctl -u "$SERVICE_NAME" -f
    exit 0
    ;;
  start)
    sudo systemctl start "$SERVICE_NAME"
    echo "[+] Service $SERVICE_NAME started."
    exit 0
    ;;
  stop)
    sudo systemctl stop "$SERVICE_NAME"
    echo "[+] Service $SERVICE_NAME stopped."
    exit 0
    ;;
  restart)
    sudo systemctl restart "$SERVICE_NAME"
    echo "[+] Service $SERVICE_NAME restarted."
    exit 0
    ;;
  uninstall)
    echo "[*] Removing $SERVICE_NAME service..."
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    sudo rm -f "$SERVICE_FILE"
    sudo systemctl daemon-reload
    echo "[+] $SERVICE_NAME service removed successfully."
    exit 0
    ;;
esac

# ----------------- Install / Setup Flow -----------------

# Dependencies
for cmd in curl unzip openssl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "[*] Installing missing dependency: $cmd..."
    if command -v apt-get &>/dev/null; then
      sudo apt-get update -qq && sudo apt-get install -y -qq "$cmd"
    elif command -v yum &>/dev/null; then
      sudo yum install -y "$cmd"
    fi
  fi
done

# Architecture detection
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ZIP_NAME="Xray-linux-64.zip" ;;
  aarch64|arm64) ZIP_NAME="Xray-linux-arm64-v8a.zip" ;;
  *) echo "[!] Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Download Xray binary
if [[ ! -f "$SCRIPT_DIR/xray" ]]; then
  echo "[*] Downloading Xray-core $XRAY_VER for $ARCH..."
  curl -sL "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/$ZIP_NAME" -o xray.zip
  unzip -q -o xray.zip xray geoip.dat geosite.dat 2>/dev/null || unzip -q -o xray.zip
  rm -f xray.zip
  chmod +x "$SCRIPT_DIR/xray"
  echo "[+] Xray binary installed."
fi

# Generate TLS certificates
if [[ ! -f "$SCRIPT_DIR/cert.pem" || ! -f "$SCRIPT_DIR/key.pem" ]]; then
  echo "[*] Generating self-signed TLS certificate for $SNI..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$SCRIPT_DIR/key.pem" -out "$SCRIPT_DIR/cert.pem" -days 365 \
    -subj "/CN=$SNI" 2>/dev/null
  echo "[+] Certificate generated."
fi

CERT_SHA256=$(openssl x509 -in "$SCRIPT_DIR/cert.pem" -outform DER | sha256sum | awk '{print $1}')
PUBLIC_IP=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me || echo "<YOUR_SERVER_PUBLIC_IP>")

# Generate Xray config.json
cat <<EOF > "$SCRIPT_DIR/config.json"
{
  "log": {
    "loglevel": "warning"
  },
  "reverse": {
    "portals": [
      {
        "tag": "portal",
        "domain": "reverse.local"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": $SOCKS_PORT,
      "listen": "0.0.0.0",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "tag": "http-in",
      "port": $HTTP_PORT,
      "listen": "0.0.0.0",
      "protocol": "http",
      "settings": {}
    },
    {
      "tag": "portal-in",
      "port": $PORT,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$SCRIPT_DIR/cert.pem",
              "keyFile": "$SCRIPT_DIR/key.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {
            "Host": "$SNI"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["portal-in"],
        "outboundTag": "portal"
      },
      {
        "type": "field",
        "inboundTag": ["socks-in", "http-in"],
        "outboundTag": "portal"
      }
    ]
  }
}
EOF

# Install systemd service
echo "[*] Creating systemd service: $SERVICE_NAME..."
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=g2reverse Xray Portal Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/xray run -c $SCRIPT_DIR/config.json
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"
sleep 1

# Output status & parameters
echo "============================================================"
echo "      g2reverse Service Installed and Running!              "
echo "============================================================"
echo "[+] Service:             $SERVICE_NAME (active/running)"
echo "[+] Portal Inbound:      0.0.0.0:$PORT (VLESS WS+TLS)"
echo "[+] Local SOCKS5:        0.0.0.0:$SOCKS_PORT"
echo "[+] Local HTTP:          0.0.0.0:$HTTP_PORT"
echo "------------------------------------------------------------"
echo "[>] Fill these into GitHub Actions (Run workflow):"
echo "    • Your Public IP:       $PUBLIC_IP"
echo "    • Your Forwarded Port:  $PORT"
echo "    • Certificate SHA256:   $CERT_SHA256"
if [[ "$SNI" != "api.github.com" ]]; then
  echo "    • SNI / Host:           $SNI"
fi
if [[ "$WS_PATH" != "/api/v3/user/repos" ]]; then
  echo "    • WebSocket Path:       $WS_PATH"
fi
echo "============================================================"
echo "[i] Useful service commands:"
echo "    ./server.sh status   - Check status and view GitHub parameters"
echo "    ./server.sh logs     - View real-time service logs"
echo "    ./server.sh restart  - Restart service"
echo "    ./server.sh stop     - Stop service"
echo "    ./server.sh uninstall- Remove service"
echo "============================================================"
