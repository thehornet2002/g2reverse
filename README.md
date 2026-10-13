# g2reverse

A secure, camouflaged reverse proxy tunnel powered by **Xray-core** (VLESS WebSocket + TLS) and **GitHub Actions**, bypassing network restrictions without requiring a dedicated external VPS.

---

## Architecture & How It Works

1. **Client / Portal (Your machine or local server):**
   - Runs an Xray Reverse Portal listening on your chosen forwarded port (e.g. `8443`).
   - Inbound traffic is encapsulated in `VLESS` over `WebSocket + TLS` with domain camouflage (e.g., `api.github.com`).
   - Opens local proxy endpoints for your browser and applications:
     - **SOCKS5:** `127.0.0.1:10808`
     - **HTTP:** `127.0.0.1:10809`

2. **Server / Bridge (GitHub Actions runner):**
   - An ephemeral Ubuntu runner connects outbound to your public IP and forwarded port.
   - The reverse bridge channels unhindered internet back through the established tunnel to your local proxy ports.

---

## Prerequisites

- **Fixed/Broadband Internet:** A connection capable of port forwarding (Fiber, VDSL, ADSL). Mobile/cellular connections behind Carrier-Grade NAT (CGNAT) require a static/public IP from your ISP.
- **Port Forwarding:** Forward an external TCP port (e.g. `8443`) in your router settings to your host machine.

---

## Quick Start

### 1. Router Port Forwarding
1. Access your router admin dashboard (typically `192.168.1.1`).
2. Navigate to **Port Forwarding** / **Virtual Server**.
3. Create a rule:
   - **Internal IP:** Your machine's local IP (e.g., `192.168.1.100`)
   - **External & Internal Port:** `8443` (or any custom port)
   - **Protocol:** `TCP`

---

### 2. Run the Client

#### Option A: Windows / Desktop (GUI)
1. Install dependencies and run:
   ```bash
   pip install cryptography
   python client_gui.py
   ```
2. Enter your **Public IP** and **Forwarded Port**.
3. Click **Start Portal**.
4. Click **Copy SHA256** to copy the certificate fingerprint for GitHub Actions.

#### Option B: Linux Server (Systemd Service)
Run the self-contained script to install and launch as a managed service:
```bash
chmod +x server.sh
sudo ./server.sh --port 8443
```
- **Service Status & Parameters:** `sudo ./server.sh status`
- **Live Logs:** `sudo ./server.sh logs`
- **Restart Service:** `sudo ./server.sh restart`
- **Stop Service:** `sudo ./server.sh stop`

---

### 3. Launch GitHub Actions Workflow

1. Fork or push this repository to your personal GitHub account (Private repository recommended).
2. Go to the **Actions** tab and select **Xray Reverse Bridge (Camouflaged)**.
3. Click **Run workflow** and provide:
   - **Your Public IP:** Your router/server public IP address.
   - **Your Forwarded Port:** Forwarded port (default `8443`).
   - **Certificate SHA256:** Copied from the client (optional; auto-detected if reachable).
   - **SNI / Host:** Camouflage domain (default `api.github.com`).
   - **WebSocket Path:** WebSocket endpoint path (default `/api/v3/user/repos`).
   - **Session Duration:** Runner lifetime (up to `6h`).
4. Click the green **Run workflow** button.

---

### 4. Connect to the Free Web

Once the GitHub Action status turns green, configure your proxy client (browser, Telegram, system proxy):

- **SOCKS5:** `127.0.0.1:10808`
- **HTTP:** `127.0.0.1:10809`

---

## File Overview

| File | Description |
|---|---|
| `client_gui.py` | Desktop GUI client (Tkinter) with certificate management and live logging |
| `server.sh` | Self-contained Linux systemd service installer and manager |
| `.github/workflows/reverse-bridge.yml` | GitHub Actions reverse bridge workflow |
| `client-config.json` | Generated Xray portal configuration |
| `cert.pem` / `key.pem` | Self-signed TLS certificate and private key |

---

## Security Notes

- **Private Repository:** Keep your repository private so that your VLESS credentials and parameters remain confidential.
- **Certificate Pinning:** The workflow uses `pinnedPeerCertSha256` to authenticate the self-signed certificate against man-in-the-middle tampering.
- **Fair Use:** Free GitHub Actions runners have a maximum duration of 6 hours per job. Re-trigger the workflow when needed.
