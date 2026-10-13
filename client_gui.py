import os
import sys
import json
import ssl
import urllib.request
import zipfile
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

CONFIG_FILE = "client-config.json"
XRAY_BIN = "xray.exe" if sys.platform == "win32" else "xray"
XRAY_ZIP_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"

class XrayClientGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("g2reverse - Secure Client Portal")
        self.geometry("480x470")
        self.resizable(False, False)

        self.process = None

        self._build_ui()
        self.generate_certificates()

    def _build_ui(self):
        pad = {'padx': 10, 'pady': 5}

        # Public IP Section (Manual input)
        frame_ip = ttk.LabelFrame(self, text="تنظیمات اتصال (اینترنت مخابرات / ثابت)")
        frame_ip.pack(fill="x", **pad)

        ttk.Label(frame_ip, text="Public IP:").grid(row=0, column=0, sticky="w", **pad)
        self.entry_ip = ttk.Entry(frame_ip, width=22)
        self.entry_ip.grid(row=0, column=1, sticky="w", **pad)

        ttk.Button(frame_ip, text="کپی IP", command=self.copy_ip).grid(row=0, column=2, **pad)

        # Forwarded Port Section
        ttk.Label(frame_ip, text="Forwarded Port:").grid(row=1, column=0, sticky="w", **pad)
        self.entry_port = ttk.Entry(frame_ip, width=12)
        self.entry_port.insert(0, "8443")
        self.entry_port.grid(row=1, column=1, sticky="w", **pad)

        # Camouflage Info
        frame_camou = ttk.LabelFrame(self, text="پوشش و امنیت (GitHub Camouflage & TLS)")
        frame_camou.pack(fill="x", **pad)
        ttk.Label(frame_camou, text="SNI / Host: api.github.com", foreground="gray").pack(anchor="w", padx=10, pady=2)
        ttk.Label(frame_camou, text="Path: /api/v3/user/repos (WebSocket + TLS)", foreground="gray").pack(anchor="w", padx=10, pady=2)

        # Local Proxy Info
        frame_local = ttk.LabelFrame(self, text="پروکسی‌های محلی برای مرورگر و برنامه‌ها")
        frame_local.pack(fill="x", **pad)
        ttk.Label(frame_local, text="SOCKS5: 127.0.0.1:10808").pack(anchor="w", padx=10, pady=2)
        ttk.Label(frame_local, text="HTTP:   127.0.0.1:10809").pack(anchor="w", padx=10, pady=2)

        # Controls
        frame_ctrl = ttk.Frame(self)
        frame_ctrl.pack(fill="x", **pad)

        self.btn_toggle = ttk.Button(frame_ctrl, text="شروع کلاینت (Start)", command=self.toggle_service)
        self.btn_toggle.pack(side="left", expand=True, fill="x", padx=5)

        # Log Box
        frame_log = ttk.LabelFrame(self, text="لاگ وضعیت")
        frame_log.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(frame_log, height=7, wrap="word", bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def log(self, text):
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")

    def copy_ip(self):
        ip = self.entry_ip.get().strip()
        if ip:
            self.clipboard_clear()
            self.clipboard_append(ip)
            self.log(f"آی‌پی {ip} کپی شد.")
        else:
            messagebox.showwarning("هشدار", "ابتدا آی‌پی را در کادر وارد کنید.")

    def generate_certificates(self):
        cert_file = "cert.pem"
        key_file = "key.pem"
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            self.log("در حال تولید گواهی TLS خودامضا برای api.github.com...")
            try:
                cmd = [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key_file, "-out", cert_file, "-days", "365",
                    "-subj", "/CN=api.github.com"
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                self.log("گواهی TLS با موفقیت ایجاد شد.")
            except Exception:
                try:
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    from cryptography.hazmat.primitives import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    import datetime

                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.github.com")])
                    now = datetime.datetime.now(datetime.timezone.utc)
                    cert = (
                        x509.CertificateBuilder()
                        .subject_name(name)
                        .issuer_name(name)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now)
                        .not_valid_after(now + datetime.timedelta(days=365))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.github.com")]), critical=False)
                        .sign(key, hashes.SHA256())
                    )
                    with open(key_file, "wb") as f:
                        f.write(key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    with open(cert_file, "wb") as f:
                        f.write(cert.public_bytes(serialization.Encoding.PEM))
                    self.log("گواهی TLS با کتابخانه cryptography ایجاد شد.")
                except Exception as ex:
                    self.log(f"خطا در ایجاد گواهی TLS: {ex}")

    def get_cert_sha256(self):
        cert_file = "cert.pem"
        if not os.path.exists(cert_file):
            return None
        try:
            import hashlib
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            with open(cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        except Exception:
            return None

    def ensure_xray_binary(self):
        if os.path.exists(XRAY_BIN):
            return True
        self.log("در حال دانلود هسته Xray...")
        try:
            zip_path = "xray.zip"
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(XRAY_ZIP_URL, context=ctx) as resp, open(zip_path, "wb") as f:
                f.write(resp.read())
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(".")
            if os.path.exists(zip_path):
                os.remove(zip_path)
            self.log("دانلود هسته Xray کامل شد.")
            return True
        except Exception as e:
            self.log(f"خطا در دانلود خودکار: {e}")
            messagebox.showerror("خطا", "دانلود xray.exe ناموفق بود.\nفایل xray.exe را دستی کنار برنامه قرار دهید.")
            return False

    def update_config_port(self, port):
        config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILE)
        if not os.path.exists(config_path):
            config_path = CONFIG_FILE

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        for inbound in cfg.get("inbounds", []):
            if inbound.get("tag") == "portal-in":
                inbound["port"] = int(port)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

    def toggle_service(self):
        if self.process is None:
            self.start_service()
        else:
            self.stop_service()

    def start_service(self):
        ip = self.entry_ip.get().strip()
        port = self.entry_port.get().strip()

        if not ip:
            messagebox.showerror("خطا", "لطفاً Public IP مخابرات خود را وارد کنید.")
            return

        if not port.isdigit():
            messagebox.showerror("خطا", "پورت باید عدد باشد.")
            return

        if not self.ensure_xray_binary():
            return

        try:
            self.update_config_port(port)
            self.log(f"پورت {port} ذخیره شد.")

            self.process = subprocess.Popen(
                [os.path.abspath(XRAY_BIN), "run", "-c", CONFIG_FILE],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            self.btn_toggle.config(text="خاموش کردن کلاینت (Stop)")
            self.entry_port.config(state="disabled")
            self.entry_ip.config(state="disabled")
            sha = self.get_cert_sha256()
            if sha:
                self.log(f"اثرانگشت گواهی (Cert SHA256):\n{sha}")
            self.log(f"پورتال فعال شد. حال در GitHub Actions این IP و پورت را وارد کرده و Run workflow را بزنید.")

            threading.Thread(target=self._read_logs, daemon=True).start()

        except Exception as e:
            self.log(f"خطا در اجرا: {e}")
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
            self.btn_toggle.config(text="شروع کلاینت (Start)")
            self.entry_port.config(state="normal")
            self.entry_ip.config(state="normal")
            self.log("کلاینت متوقف شد.")

if __name__ == "__main__":
    app = XrayClientGUI()
    app.mainloop()
