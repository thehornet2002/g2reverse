import os
import sys
import json
import ssl
import hashlib
import urllib.request
import zipfile
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "client-config.json")
CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "key.pem")
XRAY_BIN = os.path.join(BASE_DIR, "xray.exe" if sys.platform == "win32" else "xray")
XRAY_ZIP_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"
UUID = "e7b99c43-4dc9-408a-b852-7b5638a16db8"

class XrayClientGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("g2reverse - Secure Client Portal")
        self.geometry("540x630")
        self.resizable(False, False)

        self.process = None

        self._build_ui()
        self.generate_certificates()

    def _build_ui(self):
        pad = {'padx': 10, 'pady': 3}

        # Public IP & Forwarded Port Section
        frame_ip = ttk.LabelFrame(self, text="Connection Endpoint Settings")
        frame_ip.pack(fill="x", **pad)

        ttk.Label(frame_ip, text="Public IP:").grid(row=0, column=0, sticky="w", **pad)
        self.entry_ip = ttk.Entry(frame_ip, width=22)
        self.entry_ip.grid(row=0, column=1, sticky="w", **pad)
        ttk.Button(frame_ip, text="Copy IP", command=self.copy_ip).grid(row=0, column=2, **pad)

        ttk.Label(frame_ip, text="Forwarded Port:").grid(row=1, column=0, sticky="w", **pad)
        self.entry_port = ttk.Entry(frame_ip, width=12)
        self.entry_port.insert(0, "8443")
        self.entry_port.grid(row=1, column=1, sticky="w", **pad)

        # Cert Fingerprint Section
        frame_cert = ttk.LabelFrame(self, text="Certificate Fingerprint (SHA256 for GitHub Actions)")
        frame_cert.pack(fill="x", **pad)

        self.entry_sha = ttk.Entry(frame_cert, width=40)
        self.entry_sha.grid(row=0, column=0, sticky="w", **pad)
        ttk.Button(frame_cert, text="Copy SHA256", command=self.copy_sha).grid(row=0, column=1, **pad)

        # Camouflage Section (SNI & Path)
        frame_camou = ttk.LabelFrame(self, text="Camouflage & TLS Settings")
        frame_camou.pack(fill="x", **pad)

        ttk.Label(frame_camou, text="SNI / Host:").grid(row=0, column=0, sticky="w", **pad)
        self.entry_sni = ttk.Entry(frame_camou, width=30)
        self.entry_sni.insert(0, "api.github.com")
        self.entry_sni.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(frame_camou, text="WS Path:").grid(row=1, column=0, sticky="w", **pad)
        self.entry_path = ttk.Entry(frame_camou, width=30)
        self.entry_path.insert(0, "/api/v3/user/repos")
        self.entry_path.grid(row=1, column=1, sticky="w", **pad)

        # Local Proxy Ports Section
        frame_local = ttk.LabelFrame(self, text="Local Proxy Ports (Browser / Apps)")
        frame_local.pack(fill="x", **pad)

        ttk.Label(frame_local, text="SOCKS5 Port:").grid(row=0, column=0, sticky="w", **pad)
        self.entry_socks = ttk.Entry(frame_local, width=12)
        self.entry_socks.insert(0, "10808")
        self.entry_socks.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(frame_local, text="HTTP Port:").grid(row=1, column=0, sticky="w", **pad)
        self.entry_http = ttk.Entry(frame_local, width=12)
        self.entry_http.insert(0, "10809")
        self.entry_http.grid(row=1, column=1, sticky="w", **pad)

        # Controls
        frame_ctrl = ttk.Frame(self)
        frame_ctrl.pack(fill="x", **pad)

        self.btn_toggle = ttk.Button(frame_ctrl, text="Start Portal", command=self.toggle_service)
        self.btn_toggle.pack(side="left", expand=True, fill="x", padx=5, pady=4)

        # Log Box
        frame_log = ttk.LabelFrame(self, text="Activity Log")
        frame_log.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(frame_log, height=7, wrap="word", bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def log(self, text):
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")

    def copy_ip(self):
        ip = self.entry_ip.get().strip()
        if ip:
            try:
                self.clipboard_clear()
                self.clipboard_append(ip)
                self.update()
                self.log(f"Public IP copied: {ip}")
            except Exception as e:
                self.log(f"Clipboard error: {e}")
        else:
            messagebox.showwarning("Warning", "Please enter your Public IP first.")

    def copy_sha(self):
        sha = self.get_cert_sha256()
        if not sha:
            sni = self.entry_sni.get().strip() or "api.github.com"
            self.generate_certificates(sni=sni, force=True)
            sha = self.get_cert_sha256()

        if sha:
            self.entry_sha.delete(0, "end")
            self.entry_sha.insert(0, sha)
            try:
                self.clipboard_clear()
                self.clipboard_append(sha)
                self.update()
                self.log("Certificate SHA256 copied to clipboard.")
            except Exception as e:
                self.log(f"Cert SHA256: {sha}")
        else:
            messagebox.showerror("Error", "Certificate file not found.")

    def get_cert_sha256(self):
        if not os.path.exists(CERT_FILE):
            return ""
        try:
            with open(CERT_FILE, "r", encoding="utf-8") as f:
                pem = f.read()
            der = ssl.PEM_cert_to_DER_cert(pem)
            return hashlib.sha256(der).hexdigest()
        except Exception as e:
            self.log(f"Error reading certificate fingerprint: {e}")
            return ""

    def generate_certificates(self, sni="api.github.com", force=False):
        if force or not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            self.log(f"Generating self-signed TLS certificate for {sni}...")
            created = False
            try:
                cmd = [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", KEY_FILE, "-out", CERT_FILE, "-days", "365",
                    "-subj", f"/CN={sni}"
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                created = True
                self.log("TLS certificate created using openssl.")
            except Exception:
                pass

            if not created:
                try:
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    from cryptography.hazmat.primitives import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    import datetime

                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni)])
                    now = datetime.datetime.now(datetime.timezone.utc)
                    cert = (
                        x509.CertificateBuilder()
                        .subject_name(name)
                        .issuer_name(name)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now)
                        .not_valid_after(now + datetime.timedelta(days=365))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(sni)]), critical=False)
                        .sign(key, hashes.SHA256())
                    )
                    with open(KEY_FILE, "wb") as f:
                        f.write(key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    with open(CERT_FILE, "wb") as f:
                        f.write(cert.public_bytes(serialization.Encoding.PEM))
                    created = True
                    self.log("TLS certificate created using cryptography.")
                except Exception as ex:
                    self.log(f"Error generating certificate: {ex}")

        sha = self.get_cert_sha256()
        if sha:
            self.entry_sha.delete(0, "end")
            self.entry_sha.insert(0, sha)

    def ensure_xray_binary(self):
        if os.path.exists(XRAY_BIN):
            return True
        self.log("Downloading Xray-core binary...")
        try:
            zip_path = os.path.join(BASE_DIR, "xray.zip")
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(XRAY_ZIP_URL, context=ctx) as resp, open(zip_path, "wb") as f:
                f.write(resp.read())
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member in ("xray.exe", "xray", "geoip.dat", "geosite.dat"):
                        zip_ref.extract(member, BASE_DIR)
            if os.path.exists(zip_path):
                os.remove(zip_path)
            self.log("Xray-core download completed.")
            return True
        except Exception as e:
            self.log(f"Download failed: {e}")
            messagebox.showerror("Error", "Failed to download xray.exe.\nPlease place xray.exe in the application folder manually.")
            return False

    def generate_config(self, port, socks_port, http_port, sni, path):
        cfg = {
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
                    "port": int(socks_port),
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"]
                    }
                },
                {
                    "tag": "http-in",
                    "port": int(http_port),
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {}
                },
                {
                    "tag": "portal-in",
                    "port": int(port),
                    "listen": "0.0.0.0",
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": UUID
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
                                    "certificateFile": CERT_FILE,
                                    "keyFile": KEY_FILE
                                }
                            ]
                        },
                        "wsSettings": {
                            "path": path,
                            "headers": {
                                "Host": sni
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
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return CONFIG_FILE

    def toggle_service(self):
        if self.process is None:
            self.start_service()
        else:
            self.stop_service()

    def start_service(self):
        ip = self.entry_ip.get().strip()
        port = self.entry_port.get().strip()
        socks_port = self.entry_socks.get().strip()
        http_port = self.entry_http.get().strip()
        sni = self.entry_sni.get().strip() or "api.github.com"
        path = self.entry_path.get().strip() or "/api/v3/user/repos"

        if not ip:
            messagebox.showerror("Error", "Please enter your Public IP.")
            return

        for p_name, p_val in [("Forwarded Port", port), ("SOCKS5 Port", socks_port), ("HTTP Port", http_port)]:
            if not p_val.isdigit():
                messagebox.showerror("Error", f"{p_name} must be a valid number.")
                return

        if not path.startswith("/"):
            path = "/" + path

        if not self.ensure_xray_binary():
            return

        try:
            self.generate_certificates(sni=sni)
            cfg_path = self.generate_config(port, socks_port, http_port, sni, path)

            self.process = subprocess.Popen(
                [XRAY_BIN, "run", "-c", cfg_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            self.btn_toggle.config(text="Stop Portal")
            for entry in (self.entry_port, self.entry_ip, self.entry_socks, self.entry_http, self.entry_sni, self.entry_path):
                entry.config(state="disabled")

            sha = self.get_cert_sha256()

            self.log("=" * 45)
            self.log("Portal successfully started.")
            self.log("Parameters for GitHub Actions:")
            self.log(f"• Your Public IP:       {ip}")
            self.log(f"• Your Forwarded Port:  {port}")
            if sha:
                self.log(f"• Certificate SHA256:   {sha}")
            self.log(f"• SNI / Host:           {sni}")
            self.log(f"• WebSocket Path:       {path}")
            self.log("-" * 45)
            self.log("Local Proxies:")
            self.log(f"• SOCKS5: 127.0.0.1:{socks_port}")
            self.log(f"• HTTP:   127.0.0.1:{http_port}")
            self.log("=" * 45)

            threading.Thread(target=self._read_logs, daemon=True).start()

        except Exception as e:
            self.log(f"Failed to start: {e}")
            self.process = None

    def _read_logs(self):
        while self.process and self.process.poll() is None:
            line = self.process.stdout.readline()
            if line:
                self.log(line.strip())

    def stop_service(self):
        if self.process:
            self.process.terminate()
            self.process = None
            self.btn_toggle.config(text="Start Portal")
            for entry in (self.entry_port, self.entry_ip, self.entry_socks, self.entry_http, self.entry_sni, self.entry_path):
                entry.config(state="normal")
            self.log("Portal stopped.")

if __name__ == "__main__":
    app = XrayClientGUI()
    app.mainloop()
