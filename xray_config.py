"""xray_config.py — تولید Xray config — Xray روی پورت داخلی 9443"""
import json
import logging
from datetime import datetime
from pathlib import Path

from config import XRAY_MAIN_CFG, XRAY_CERT_FILE, XRAY_KEY_FILE, XRAY_INTERNAL_PORT
from state  import LINKS, LINKS_LOCK

logger = logging.getLogger("RVG.xray_config")


def _is_allowed(link: dict) -> bool:
    if not link.get("active", True):
        return False
    exp = link.get("expires_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(exp):
                return False
        except Exception:
            pass
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True


async def build_xray_config() -> dict:
    """
    Xray روی پورت داخلی XRAY_INTERNAL_PORT (9443) گوش میده.
    Python proxy روی PORT (8080) همه ترافیک VPN رو به اینجا forward میکنه.
    """
    async with LINKS_LOCK:
        snapshot = {k: dict(v) for k, v in LINKS.items()}

    clients = []
    for uuid, link in snapshot.items():
        if not _is_allowed(link):
            continue
        clients.append({"id": link.get("secret", uuid), "flow": ""})
        logger.debug(f"  client: {uuid[:8]} label={link.get('label','')}")

    if not clients:
        clients = [{"id": "00000000-0000-0000-0000-000000000000", "flow": ""}]

    logger.info(f"📋 Xray config: {len(clients)} client(s) — internal port {XRAY_INTERNAL_PORT}")

    inbound = {
        "tag":      "siz10a-main",
        "listen":   "127.0.0.1",        # فقط localhost — Python proxy از اینجا forward میکنه
        "port":     XRAY_INTERNAL_PORT,
        "protocol": "vless",
        "settings": {
            "clients":    clients,
            "decryption": "none",
        },
        "streamSettings": {
            "network":  "xhttp",
            "security": "tls",
            "tlsSettings": {
                "minVersion":   "1.2",
                "certificates": [{
                    "certificateFile": XRAY_CERT_FILE,
                    "keyFile":         XRAY_KEY_FILE,
                }],
                "alpn": ["h3", "h2", "http/1.1"],
                "enableSessionResumption": True,
            },
            "xhttpSettings": {
                "path":                  "/siz",
                "host":                  "",
                "mode":                  "auto",
                "maxUploadSize":         100 * 1024 * 1024,
                "maxConcurrentUploads":  10,
                "noSSEHeader":           False,
                "scMaxEachPostBytes":    1 * 1024 * 1024,
                "scMinPostsIntervalMs":  30,
                "xPaddingBytes":         "100-1000",
            },
        },
        "sniffing": {
            "enabled":      True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly":    False,
        },
    }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [
            {"protocol": "freedom",   "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "none"}}, "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "outboundTag": "direct", "network": "tcp,udp"},
            ],
        },
    }


async def write_xray_config() -> str:
    config   = await build_xray_config()
    path     = Path(XRAY_MAIN_CFG)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = json.dumps(config, ensure_ascii=False, indent=2)
    json.loads(json_str)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_str)
    logger.info(f"✅ Xray config written → {path}")
    return str(path)


def get_port_map() -> dict:
    return {}
