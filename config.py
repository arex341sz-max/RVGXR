"""config.py — تمام تنظیمات از environment variables"""
import os
import secrets

# پورت عمومی Railway — همه ترافیک از اینجا میاد
PORT          = int(os.environ.get("PORT", 8080))
PUBLIC_PORT   = PORT  # پورت عمومی (Python proxy روی این گوش میده)

SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ADMIN_PW      = os.environ.get("ADMIN_PASSWORD", "123456")
PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")

DATA_DIR        = os.environ.get("DATA_DIR", "/data")
XRAY_CONFIG_DIR = os.environ.get("XRAY_CONFIG_DIR", "/data/xray-configs")
XRAY_BIN        = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_MAIN_CFG   = os.environ.get("XRAY_MAIN_CFG", "/data/xray-main.json")

XRAY_CERT_DIR  = os.environ.get("XRAY_CERT_DIR", "/data/certs")
XRAY_CERT_FILE = os.path.join(XRAY_CERT_DIR, "cert.pem")
XRAY_KEY_FILE  = os.path.join(XRAY_CERT_DIR, "key.pem")

# پورت‌های داخلی — Railway فقط PORT رو expose میکنه
XRAY_INTERNAL_PORT = int(os.environ.get("XRAY_INTERNAL_PORT", 9443))  # Xray روی این گوش میده
ADMIN_PORT         = int(os.environ.get("ADMIN_PORT", 8081))           # aiohttp API

SESSION_TTL = 60 * 60 * 24 * 7
