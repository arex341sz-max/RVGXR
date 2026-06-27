"""
main.py — RVG Gateway v11 | Xray-native (بدون FastAPI)

معماری:
  - Xray مستقیماً روی پورت PUBLIC (8080) → همه ترافیک VPN
  - aiohttp سبک روی ADMIN_PORT (8081) → dashboard + API
  - HTTP fallback listener روی port 8082 → health check های Railway
  - هیچ relay/proxy لازم نیست — Xray native handle می‌کنه

FIX: اضافه شدن HTTP health-check server روی port 8082
     تا Railway health check (plain HTTP) جواب درست بگیره
     به جای TLS handshake error.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import quote, parse_qs, urlparse

from aiohttp import web

from auth             import init_auth, is_valid_session, SESSION_COOKIE, SESSION_TTL
from auth             import create_session, destroy_session, hash_password, require_auth_token
from config           import ADMIN_PORT, PUBLIC_PORT, PUBLIC_DOMAIN
from core.persistence import load_state, save_state
from link_manager     import (
    generate_uuid, generate_secret, protocol_defaults,
    generate_link_url, is_allowed, is_expired, fmt_bytes,
    parse_size, PROTOCOLS_INFO,
)
from protocols        import list_protocols, get_protocol
from state            import LINKS, LINKS_LOCK, SUBS, SUBS_LOCK, AUTH, connections, stats, error_logs, hourly_traffic
from xray_manager     import start_monitor, stop_monitor, get_status, restart_xray, reload_xray, start_xray, stop_xray
from xray_config      import write_xray_config, get_port_map

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("RVG")

# ── FIX: پورت HTTP fallback برای health check Railway ────────────────────────
# Xray plain HTTP requests رو به این پورت forward میکنه (از fallback config)
HEALTH_FALLBACK_PORT = int(os.environ.get("HEALTH_FALLBACK_PORT", 8082))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", PUBLIC_DOMAIN)


def json_resp(data, status=200):
    return web.Response(
        text=json.dumps(data, ensure_ascii=False),
        content_type="application/json",
        status=status,
    )


def err(msg, status=400):
    return json_resp({"error": msg}, status)


async def _check_auth(request: web.Request) -> str | None:
    """Returns session token if valid, else None"""
    token = request.cookies.get(SESSION_COOKIE)
    if token and await is_valid_session(token):
        return token
    # also check Authorization header for API clients
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if await is_valid_session(token):
            return token
    return None


async def _require_auth(request: web.Request) -> str:
    token = await _check_auth(request)
    if not token:
        raise web.HTTPUnauthorized(text=json.dumps({"error": "unauthorized"}),
                                   content_type="application/json")
    return token


def _check_port_conflict(new_port: int, exclude_uuid: str = None) -> bool:
    for uid, link in LINKS.items():
        if exclude_uuid and uid == exclude_uuid:
            continue
        if link.get("port") == new_port:
            return True
    return False


def _build_stream_params(protocol: str, stream: str, body: dict, uid: str) -> dict:
    sp = body.get("stream_params", {}) or {}
    # برای siz10a همیشه path /siz هست (یه inbound مشترک)
    if protocol == "siz10a" or stream == "xhttp":
        sp["path"] = "/siz"
    elif stream in ("ws", "httpupgrade") and not sp.get("path"):
        prefix = {"ws": "ws", "httpupgrade": "up"}.get(stream, stream)
        sp["path"] = f"/{prefix}/{uid}"
    if stream == "grpc" and not sp.get("serviceName"):
        sp["serviceName"] = f"grpc-{uid[:8]}"
    return sp


# ── Auth routes ───────────────────────────────────────────────────────────────

async def login(request: web.Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        return err("رمز عبور اشتباه است", 401)
    token = await create_session()
    resp = json_resp({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL,
                    httponly=True, samesite="Lax", path="/")
    return resp


async def logout(request: web.Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = json_resp({"ok": True})
    resp.del_cookie(SESSION_COOKIE, path="/")
    return resp


async def me(request: web.Request):
    token = await _check_auth(request)
    return json_resp({"authenticated": token is not None})


async def change_password(request: web.Request):
    token = await _require_auth(request)
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        return err("رمز فعلی اشتباه است", 400)
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        return err("رمز جدید حداقل ۴ کاراکتر", 400)
    AUTH["password_hash"] = hash_password(new)
    from state import SESSIONS, SESSIONS_LOCK
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return json_resp({"ok": True})


# ── Links routes ──────────────────────────────────────────────────────────────

async def create_link(request: web.Request):
    await _require_auth(request)
    body     = await request.json()
    protocol = str(body.get("protocol", "siz10a")).lower().strip()
    stream   = str(body.get("stream", "")).lower().strip()
    tls      = bool(body.get("tls", True))
    label    = (body.get("label") or "لینک جدید").strip()[:60]
    note     = (body.get("note") or "").strip()[:200]
    sub_id   = body.get("sub_id") or None
    port     = int(body.get("port", 0))
    reality  = bool(body.get("reality", False))

    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size(lv, lu)

    exp_days   = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None

    try:
        proto = get_protocol(protocol)
    except ValueError:
        return err(f"پروتکل نامعتبر: {protocol}", 400)

    if not stream:
        stream = proto.default_stream
    if stream not in proto.stream_modes:
        return err(f"استریم '{stream}' برای {protocol} پشتیبانی نمی‌شود", 400)
    if reality and not proto.supports_reality:
        return err(f"Reality برای {protocol} پشتیبانی نمی‌شود", 400)
    if not proto.supports_tls:
        tls = False

    if port == 0:
        port = 443

    uid    = generate_uuid()
    secret = generate_secret(protocol)
    stream_params = _build_stream_params(protocol, stream, body, uid)

    entry = {
        "uuid":                uid,
        "secret":              secret,
        "protocol":            protocol,
        "stream":              "xhttp",   # همیشه xhttp برای Xray-native
        "tls":                 tls,
        "stream_params":       stream_params,
        "port":                port,
        "label":               label,
        "limit_bytes":         limit_bytes,
        "used_bytes":          0,
        "created_at":          datetime.now().isoformat(),
        "active":              True,
        "expires_at":          expires_at,
        "note":                note,
        "is_default":          False,
        "sub_id":              sub_id,
        "reality":             reality,
        "reality_pbk":         body.get("reality_pbk", ""),
        "reality_sid":         body.get("reality_sid", ""),
        "reality_sni":         body.get("reality_sni", ""),
        "reality_fingerprint": body.get("reality_fingerprint", "chrome"),
        "sni":                 body.get("sni", ""),
        "fingerprint":         body.get("fingerprint", "chrome"),
        "alpn":                body.get("alpn", "h3"),
    }

    async with LINKS_LOCK:
        LINKS[uid] = entry

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(reload_xray())
    asyncio.create_task(save_state())

    host     = _host()
    link_url = generate_link_url(entry, host)
    return json_resp({"uuid": uid, **entry, "expired": False,
                      "link_url": link_url, "sub_url": f"https://{host}/sub/{uid}"})


async def list_links(request: web.Request):
    await _require_auth(request)
    host = _host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        result.append({
            "uuid": uid, **d,
            "expired":   is_expired(d),
            "link_url":  generate_link_url(d, host),
            "sub_url":   f"https://{host}/sub/{uid}",
            "used_fmt":  fmt_bytes(d.get("used_bytes", 0)),
            "limit_fmt": "∞" if not d.get("limit_bytes") else fmt_bytes(d["limit_bytes"]),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return json_resp({"links": result})


async def update_link(request: web.Request):
    await _require_auth(request)
    uid  = request.match_info["uid"]
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            return err("link not found", 404)
        link    = LINKS[uid]
        old_sub = link.get("sub_id")

        for field in ("active", "label", "note", "sni", "fingerprint", "alpn",
                      "reality", "reality_pbk", "reality_sid", "reality_sni", "reality_fingerprint"):
            if field in body:
                link[field] = body[field]

        if body.get("reset_usage"):
            link["used_bytes"] = 0

        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            link["limit_bytes"] = 0 if lv <= 0 else parse_size(lv, body.get("limit_unit", "GB"))

        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None

        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids: ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids: ids.append(uid)

    asyncio.create_task(reload_xray())
    asyncio.create_task(save_state())
    return json_resp({"ok": True})


async def delete_link(request: web.Request):
    await _require_auth(request)
    uid = request.match_info["uid"]
    async with LINKS_LOCK:
        if uid not in LINKS:
            return err("link not found", 404)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids: ids.remove(uid)

    asyncio.create_task(reload_xray())
    asyncio.create_task(save_state())
    return json_resp({"ok": True, "deleted": uid})


async def clone_link(request: web.Request):
    await _require_auth(request)
    uid = request.match_info["uid"]
    async with LINKS_LOCK:
        if uid not in LINKS:
            return err("کانفیگ پیدا نشد", 404)
        original = LINKS[uid]
        new_uid    = generate_uuid()
        new_secret = generate_secret(original.get("protocol", "siz10a"))
        new_link = {
            **original,
            "uuid":         new_uid,
            "secret":       new_secret,
            "label":        f"{original.get('label', 'لینک')} (کپی)",
            "created_at":   datetime.now().isoformat(),
            "used_bytes":   0,
            "is_default":   False,
            "stream_params": {"path": "/siz"},
        }
        LINKS[new_uid] = new_link
        sub_id = original.get("sub_id")
        if sub_id:
            async with SUBS_LOCK:
                if sub_id in SUBS:
                    ids = SUBS[sub_id].setdefault("link_ids", [])
                    if new_uid not in ids: ids.append(new_uid)

    asyncio.create_task(reload_xray())
    asyncio.create_task(save_state())
    host = _host()
    link_url = generate_link_url(new_link, host)
    return json_resp({
        "uuid": new_uid, **new_link, "expired": False,
        "link_url": link_url,
        "sub_url": f"https://{host}/sub/{new_uid}",
        "message": "✅ کانفیگ کپی شد",
    })


# ── Subs routes ───────────────────────────────────────────────────────────────

async def create_sub(request: web.Request):
    await _require_auth(request)
    body     = await request.json()
    name     = (body.get("name") or "گروه جدید").strip()[:60]
    desc     = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id   = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name":          name,
            "desc":          desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key":      uuid_key,
            "created_at":    datetime.now().isoformat(),
            "link_ids":      [],
        }
    asyncio.create_task(save_state())
    host = _host()
    return json_resp({"sub_id": sub_id, **SUBS[sub_id], "password_hash": None,
                      "has_password": bool(password),
                      "public_url": f"https://{host}/p/{uuid_key}",
                      "sub_url": f"https://{host}/sub-group/{uuid_key}"})


async def list_subs(request: web.Request):
    await _require_auth(request)
    host = _host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        ids          = s.get("link_ids", [])
        active_count = sum(1 for lid in ids if is_allowed(snap_links.get(lid)))
        total_used   = sum(snap_links[lid].get("used_bytes", 0) for lid in ids if lid in snap_links)
        result.append({
            "sub_id": sid, **s, "password_hash": None,
            "has_password":     s.get("password_hash") is not None,
            "links_count":      len(ids),
            "active_count":     active_count,
            "total_used_bytes": total_used,
            "total_used_fmt":   fmt_bytes(total_used),
            "public_url":       f"https://{host}/p/{s['uuid_key']}",
            "sub_url":          f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return json_resp({"subs": result})


async def update_sub(request: web.Request):
    await _require_auth(request)
    sub_id = request.match_info["sub_id"]
    body   = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            return err("sub not found", 404)
        s = SUBS[sub_id]
        if "name" in body: s["name"] = str(body["name"])[:60]
        if "desc" in body: s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    asyncio.create_task(save_state())
    return json_resp({"ok": True})


async def delete_sub(request: web.Request):
    await _require_auth(request)
    sub_id = request.match_info["sub_id"]
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            return err("sub not found", 404)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    return json_resp({"ok": True, "deleted": sub_id})


async def assign_link_to_sub(request: web.Request):
    await _require_auth(request)
    sub_id  = request.match_info["sub_id"]
    body    = await request.json()
    link_id = str(body.get("link_id", ""))
    action  = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            return err("sub not found", 404)
        ids = SUBS[sub_id].setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids: ids.append(link_id)
        else:
            if link_id in ids: ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return json_resp({"ok": True})


# ── Xray routes ───────────────────────────────────────────────────────────────

async def xray_status(request: web.Request):
    await _require_auth(request)
    return json_resp(get_status())


async def xray_restart(request: web.Request):
    await _require_auth(request)
    ok = await restart_xray()
    return json_resp({"ok": ok})


async def xray_reload(request: web.Request):
    await _require_auth(request)
    ok = await reload_xray()
    return json_resp({"ok": ok})


async def xray_start_ep(request: web.Request):
    await _require_auth(request)
    ok = await start_xray()
    return json_resp({"ok": ok})


async def xray_stop_ep(request: web.Request):
    await _require_auth(request)
    await stop_xray()
    return json_resp({"ok": True})


async def xray_ports_ep(request: web.Request):
    await _require_auth(request)
    return json_resp({"port_map": get_port_map()})


# ── Stats routes ──────────────────────────────────────────────────────────────

async def get_stats(request: web.Request):
    await _require_auth(request)
    async with LINKS_LOCK:
        snap = dict(LINKS)
    from collections import defaultdict
    proto_counts: dict = defaultdict(int)
    for d in snap.values():
        if is_allowed(d):
            proto_counts[d.get("protocol", "siz10a")] += 1
    s = int(time.time() - stats["start_time"])
    uptime = f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
    return json_resp({
        "active_connections": len(connections),
        "total_traffic_mb":   round(stats["total_bytes"] / (1024**2), 2),
        "total_requests":     stats["total_requests"],
        "total_errors":       stats["total_errors"],
        "uptime":             uptime,
        "timestamp":          datetime.now().isoformat(),
        "hourly":             dict(hourly_traffic),
        "recent_errors":      list(error_logs)[-10:],
        "links_count":        len(snap),
        "active_links":       sum(1 for l in snap.values() if is_allowed(l)),
        "expired_links":      sum(1 for l in snap.values() if is_expired(l)),
        "subs_count":         len(SUBS),
        "protocol_counts":    dict(proto_counts),
        "xray":               get_status(),
    })


async def health(request: web.Request):
    s = int(time.time() - stats["start_time"])
    uptime = f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
    return json_resp({
        "status":      "ok",
        "connections": len(connections),
        "uptime":      uptime,
        "xray":        get_status()["running"],
    })


# ── Protocols routes ──────────────────────────────────────────────────────────

async def api_protocols(request: web.Request):
    return json_resp({"protocols": list_protocols()})


async def api_protocol_modes(request: web.Request):
    name = request.match_info["name"]
    try:
        proto = get_protocol(name)
        return json_resp({"protocol": name, "modes": proto.stream_modes})
    except ValueError:
        return err("پروتکل پیدا نشد", 404)


# ── Subscription routes ───────────────────────────────────────────────────────

async def sub_single(request: web.Request):
    uuid = request.match_info["uuid"]
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_allowed(link):
        raise web.HTTPNotFound()
    url = generate_link_url(link, _host())
    if not url:
        raise web.HTTPInternalServerError()
    content = base64.b64encode(url.encode()).decode()
    return web.Response(
        text=content, content_type="text/plain",
        headers={
            "profile-title": quote(link["label"]),
            "support-url":   "https://t.me/CodeBoxo",
            "profile-update-interval": "12",
        },
    )


async def sub_all(request: web.Request):
    await _require_auth(request)
    host = _host()
    async with LINKS_LOCK:
        lines = [generate_link_url(d, host) for d in LINKS.values() if is_allowed(d)]
    lines   = [l for l in lines if l]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return web.Response(text=content, content_type="text/plain")


async def sub_group(request: web.Request):
    uuid_key = request.match_info["uuid_key"]
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise web.HTTPNotFound()
    if sub.get("password_hash"):
        pw = request.rel_url.query.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise web.HTTPForbidden()
    host     = _host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        lines = [generate_link_url(LINKS[lid], host)
                 for lid in link_ids if lid in LINKS and is_allowed(LINKS[lid])]
    lines   = [l for l in lines if l]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return web.Response(
        text=content, content_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "support-url":   "https://t.me/CodeBoxo",
            "profile-update-interval": "12",
        },
    )


async def public_sub_data(request: web.Request):
    uuid_key = request.match_info["uuid_key"]
    async with SUBS_LOCK:
        sub_entry = next(
            ((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None
        )
    if not sub_entry:
        raise web.HTTPNotFound()
    sub_id, sub = sub_entry
    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.rel_url.query.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return json_resp({"locked": True, "name": sub["name"]})
    host     = _host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)
    links_out   = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link: continue
        conn_count   = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        links_out.append({
            "uuid":        lid,
            "label":       link["label"],
            "protocol":    link.get("protocol", "siz10a"),
            "stream":      link.get("stream", "xhttp"),
            "active":      is_allowed(link),
            "used_bytes":  link.get("used_bytes", 0),
            "used_fmt":    fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt":   "∞" if not link.get("limit_bytes") else fmt_bytes(link["limit_bytes"]),
            "expires_at":  link.get("expires_at"),
            "link_url":    generate_link_url(link, host),
            "sub_url":     f"https://{host}/sub/{lid}",
            "connections": conn_count,
        })
    total_used = sum(l["used_bytes"] for l in links_out)
    return json_resp({
        "locked":             False,
        "name":               sub["name"],
        "desc":               sub.get("desc", ""),
        "sub_url":            f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt":     fmt_bytes(total_used),
        "links":              links_out,
    })


# ── Pages (HTML) ──────────────────────────────────────────────────────────────

async def root(request: web.Request):
    return json_resp({
        "service":  "RVG Gateway",
        "version":  "11.0",
        "status":   "active",
        "arch":     "Xray-native (no relay)",
        "xray_port": PUBLIC_PORT,
        "protocols": list(PROTOCOLS_INFO),
        "channel":  "https://t.me/CodeBoxo",
    })


async def login_page(request: web.Request):
    if await _check_auth(request):
        raise web.HTTPFound("/dashboard")
    from pages.login import HTML as LOGIN_HTML
    return web.Response(text=LOGIN_HTML, content_type="text/html")


async def dashboard_page(request: web.Request):
    if not await _check_auth(request):
        raise web.HTTPFound("/login")
    from pages.dashboard import HTML as DASH_HTML
    return web.Response(text=DASH_HTML, content_type="text/html")


async def public_page(request: web.Request):
    uuid_key = request.match_info["uuid_key"]
    from pages.public import get_html
    return web.Response(text=get_html(uuid_key), content_type="text/html")


# ── Startup ───────────────────────────────────────────────────────────────────

async def _ensure_default_link():
    from config import SECRET_KEY
    async with LINKS_LOCK:
        if any(l.get("is_default") for l in LINKS.values()):
            return
        uid = hashlib.sha256(f"default{SECRET_KEY}".encode()).hexdigest()
        uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
        if uid not in LINKS:
            LINKS[uid] = {
                "uuid":                uid,
                "secret":              uid,
                "protocol":            "siz10a",
                "stream":              "xhttp",
                "tls":                 True,
                "stream_params":       {"path": "/siz"},
                "label":               "SIZ10A Ultra (پیش‌فرض)",
                "port":                443,
                "limit_bytes":         0,
                "used_bytes":          0,
                "created_at":          datetime.now().isoformat(),
                "active":              True,
                "expires_at":          None,
                "note":                "لینک پیش‌فرض — SIZ10A XHTTP Ultra",
                "is_default":          True,
                "sub_id":              None,
                "reality":             False,
                "reality_pbk":         "",
                "reality_sid":         "",
                "reality_sni":         "",
                "reality_fingerprint": "chrome",
                "sni":                 "",
                "fingerprint":         "chrome",
                "alpn":                "h3",
            }
            asyncio.create_task(save_state())


def _ensure_self_signed_cert() -> bool:
    import subprocess
    from config import XRAY_CERT_DIR, XRAY_CERT_FILE, XRAY_KEY_FILE
    if os.path.exists(XRAY_CERT_FILE) and os.path.exists(XRAY_KEY_FILE):
        logger.info(f"🔐 Cert already exists → {XRAY_CERT_DIR}/")
        return True
    os.makedirs(XRAY_CERT_DIR, exist_ok=True)
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", XRAY_KEY_FILE, "-out", XRAY_CERT_FILE,
             "-days", "3650", "-nodes", "-subj", "/CN=rvg-gateway"],
            check=True, capture_output=True, text=True,
        )
        logger.info(f"🔐 Self-signed cert generated → {XRAY_CERT_DIR}/")
        return True
    except Exception as e:
        logger.error(f"❌ Cert generation error: {e}")
        return False


# ── App builder ───────────────────────────────────────────────────────────────

def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/",                         root)
    app.router.add_get("/login",                    login_page)
    app.router.add_get("/dashboard",                dashboard_page)
    app.router.add_get("/p/{uuid_key}",             public_page)

    # Auth
    app.router.add_post("/api/login",               login)
    app.router.add_post("/api/logout",              logout)
    app.router.add_get("/api/me",                   me)
    app.router.add_post("/api/change-password",     change_password)

    # Links
    app.router.add_post("/api/links",               create_link)
    app.router.add_get("/api/links",                list_links)
    app.router.add_patch("/api/links/{uid}",        update_link)
    app.router.add_delete("/api/links/{uid}",       delete_link)
    app.router.add_post("/api/links/{uid}/clone",   clone_link)

    # Subs
    app.router.add_post("/api/subs",                create_sub)
    app.router.add_get("/api/subs",                 list_subs)
    app.router.add_patch("/api/subs/{sub_id}",      update_sub)
    app.router.add_delete("/api/subs/{sub_id}",     delete_sub)
    app.router.add_post("/api/subs/{sub_id}/links", assign_link_to_sub)

    # Xray
    app.router.add_get("/api/xray/status",          xray_status)
    app.router.add_post("/api/xray/restart",        xray_restart)
    app.router.add_post("/api/xray/reload",         xray_reload)
    app.router.add_post("/api/xray/start",          xray_start_ep)
    app.router.add_post("/api/xray/stop",           xray_stop_ep)
    app.router.add_get("/api/xray/ports",           xray_ports_ep)

    # Stats
    app.router.add_get("/stats",                    get_stats)
    app.router.add_get("/health",                   health)

    # Protocols
    app.router.add_get("/api/protocols",            api_protocols)
    app.router.add_get("/api/protocols/{name}/modes", api_protocol_modes)

    # Subscriptions
    app.router.add_get("/sub/{uuid}",               sub_single)
    app.router.add_get("/sub-all",                  sub_all)
    app.router.add_get("/sub-group/{uuid_key}",     sub_group)
    app.router.add_get("/api/public/sub/{uuid_key}", public_sub_data)

    return app


# ── FIX: HTTP Health-check server (fallback از Xray) ─────────────────────────
# Railway health check با plain HTTP به port 8080 وصل میشه
# Xray این درخواست‌ها رو به port 8082 forward میکنه (از طریق fallback config)
# این server روی 8082 گوش میده و /health رو جواب میده

async def _http_health_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    یه HTTP handler ساده برای health check های Railway.
    Xray plain HTTP requests رو از port 8080 به اینجا forward میکنه.
    """
    try:
        # خوندن request header
        data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        request_line = data.decode("utf-8", errors="replace").split("\r\n")[0]

        s = int(time.time() - stats["start_time"])
        uptime = f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
        body = json.dumps({
            "status":      "ok",
            "connections": len(connections),
            "uptime":      uptime,
            "xray":        get_status()["running"],
        })
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    init_auth()
    await load_state()
    await _ensure_default_link()
    _ensure_self_signed_cert()
    await start_monitor()

    # Admin API (aiohttp) روی پورت 8081
    app = build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", ADMIN_PORT)
    await site.start()

    # FIX: HTTP health-check server روی پورت 8082
    # این server plain HTTP requests از Xray fallback رو handle میکنه
    health_server = await asyncio.start_server(
        _http_health_handler,
        "127.0.0.1",   # فقط localhost — Xray از همین host forward میکنه
        HEALTH_FALLBACK_PORT,
    )
    logger.info(f"🏥 HTTP health-check server listening on 127.0.0.1:{HEALTH_FALLBACK_PORT}")

    logger.info(f"🚀 RVG Gateway v11 — Xray-native architecture")
    logger.info(f"📡 Xray (VPN) listening on port {PUBLIC_PORT}")
    logger.info(f"🖥  Admin API listening on port {ADMIN_PORT}")
    logger.info(f"📋 Protocols: {', '.join(PROTOCOLS_INFO)}")

    try:
        await asyncio.Event().wait()
    finally:
        health_server.close()
        await health_server.wait_closed()
        await stop_monitor()
        await save_state()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
