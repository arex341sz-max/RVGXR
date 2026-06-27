"""config.py — تمام تنظیمات از environment variables (IMPROVED)"""
import os
import secrets

# ═══════════════════════════════════════════════════════════════════════════════
# 🔧 PORT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
# 
# PORT / PUBLIC_PORT: پورتی که Xray بر روی آن گوش می‌دهد (VPN traffic)
#   - Default: 8080
#   - ⚠️ نکته: این پورت باید public باشد و از طریق دومین دسترسی داشته باشید
#
# ADMIN_PORT: پورتی که Admin API/Dashboard بر روی آن گوش می‌دهد
#   - Default: 8081
#   - ℹ️ این پورت عموماً internal است و نباید public باشد
#

PORT          = int(os.environ.get("PORT", 8080))
PUBLIC_PORT   = PORT  # Xray مستقیم روی همین پورت گوش میده
ADMIN_PORT    = int(os.environ.get("ADMIN_PORT", 8081))


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ADMIN_PW      = os.environ.get("ADMIN_PASSWORD", "123456")
PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")


# ═══════════════════════════════════════════════════════════════════════════════
# 📁 DIRECTORY & XRAY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DATA_DIR        = os.environ.get("DATA_DIR", "/data")
XRAY_CONFIG_DIR = os.environ.get("XRAY_CONFIG_DIR", "/data/xray-configs")
XRAY_BIN        = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_MAIN_CFG   = os.environ.get("XRAY_MAIN_CFG", "/data/xray-main.json")


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 TLS/HTTPS CERTIFICATE PATHS
# ═══════════════════════════════════════════════════════════════════════════════
# 
# ✅ Self-signed certificates برای XHTTP+TLS
# توجه: درصورت نیاز به production، certificates را از Let's Encrypt دریافت کنید
#

XRAY_CERT_DIR  = os.environ.get("XRAY_CERT_DIR", "/data/certs")
XRAY_CERT_FILE = os.path.join(XRAY_CERT_DIR, "cert.pem")
XRAY_KEY_FILE  = os.path.join(XRAY_CERT_DIR, "key.pem")


# ═══════════════════════════════════════════════════════════════════════════════
# 🕐 SESSION & CACHE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SESSION_TTL = 60 * 60 * 24 * 7  # 7 days in seconds


# ═══════════════════════════════════════════════════════════════════════════════
# 📊 OPTIONAL: MONITORING & LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

ENABLE_STATS    = os.environ.get("ENABLE_STATS", "true").lower() == "true"
LOG_LEVEL       = os.environ.get("LOG_LEVEL", "INFO")
