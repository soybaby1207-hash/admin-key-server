from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import hmac
import time
import secrets
import string
import os
import requests

app = Flask(__name__)

ALLOWED_ORIGINS = ["https://soybaby1207-hash.github.io"]
CORS(app, origins=ALLOWED_ORIGINS)

# Estas variables DEBEN configurarse en Render (Environment). Sin valores por defecto.
SECRET = os.environ["SECRET_KEY"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
PANEL_PASSWORD = os.environ["PANEL_PASSWORD"]
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

PERMANENT = 9999999999


def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


def sb_get(filters=""):
    query = f"{filters}&" if filters else ""
    r = requests.get(f"{SUPABASE_URL}/rest/v1/keys?{query}order=created_at.desc",
                     headers=sb_headers(), timeout=15)
    return r.json()


def sb_insert(data):
    r = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=sb_headers(), json=data, timeout=15)
    return r.json()


def sb_update(id, data):
    return requests.patch(f"{SUPABASE_URL}/rest/v1/keys?id=eq.{id}",
                          headers=sb_headers(), json=data, timeout=15)


def sb_delete(id):
    return requests.delete(f"{SUPABASE_URL}/rest/v1/keys?id=eq.{id}",
                           headers=sb_headers(), timeout=15)


def sb_find_key(key):
    r = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=sb_headers(),
                     params={"key": f"eq.{key}"}, timeout=15)
    data = r.json()
    return data[0] if isinstance(data, list) and data else None


def simple_hash(text):
    return hashlib.sha256((SECRET + text).encode("utf-8")).hexdigest()[:8].upper()


def random_part():
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(4))


def check_password(given, expected):
    return hmac.compare_digest(str(given or "").encode(), expected.encode())


def get_json():
    return request.get_json(silent=True) or {}


@app.route("/")
def index():
    return "Admin Key Server funcionando ✅"


@app.route("/generate", methods=["POST"])
def generate():
    data = get_json()
    if not check_password(data.get("password"), ADMIN_PASSWORD):
        return jsonify({"success": False, "error": "No autorizado"}), 403
    try:
        duration = int(data.get("duration", 3600))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Duración inválida"}), 400
    username = str(data.get("username", "")).strip().upper()
    if not username:
        return jsonify({"success": False, "error": "El usuario es obligatorio"}), 400
    now = int(time.time())
    expiry = PERMANENT if duration == 0 else now + duration
    signature = simple_hash(str(expiry))
    key = f"ADMIN-{random_part()}-{expiry}-{signature}"
    expiry_readable = "Permanente" if duration == 0 else time.strftime(
        "%d/%m/%Y %H:%M", time.localtime(expiry))
    result = sb_insert({"key": key, "username": username, "expiry": expiry,
                        "expiry_readable": expiry_readable, "created_at": now, "active": 1})
    if isinstance(result, list) and len(result) > 0:
        return jsonify({"success": True, "key": key, "expiry": expiry_readable, "username": username})
    return jsonify({"success": False, "error": "Error guardando la key"}), 500


@app.route("/verify", methods=["POST"])
def verify():
    data = get_json()
    key = str(data.get("key", "")).strip()
    username = str(data.get("username", "")).strip().upper()
    parts = key.split("-")
    if len(parts) != 4 or parts[0] != "ADMIN":
        return jsonify({"valid": False, "reason": "Key invalida"})
    expiry, signature = parts[2], parts[3]
    if not expiry.isdigit() or not hmac.compare_digest(signature, simple_hash(expiry)):
        return jsonify({"valid": False, "reason": "Key invalida"})
    now = int(time.time())
    expiry_int = int(expiry)
    if expiry_int != PERMANENT and now > expiry_int:
        return jsonify({"valid": False, "reason": "Key expirada"})
    row = sb_find_key(key)
    if not row:
        return jsonify({"valid": False, "reason": "Key no existe"})
    if row["active"] != 1:
        return jsonify({"valid": False, "reason": "Key desactivada"})
    if row["username"] != username:
        return jsonify({"valid": False, "reason": "Usuario incorrecto"})
    if expiry_int == PERMANENT:
        time_left = "Permanente"
    else:
        seconds_left = expiry_int - now
        days = seconds_left // 86400
        hours = (seconds_left % 86400) // 3600
        minutes = (seconds_left % 3600) // 60
        if days > 0:
            time_left = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            time_left = f"{hours}h {minutes}m"
        else:
            time_left = f"{minutes}m"
    return jsonify({"valid": True, "reason": "OK", "time_left": time_left})


@app.route("/panel/keys", methods=["POST"])
def panel_keys():
    data = get_json()
    if not check_password(data.get("password"), PANEL_PASSWORD):
        return jsonify({"success": False, "error": "No autorizado"}), 403
    rows = sb_get()
    now = int(time.time())
    keys = [{
        "id": row["id"], "key": row["key"], "username": row["username"],
        "expiry_readable": row["expiry_readable"], "active": row["active"],
        "expired": row["expiry"] != PERMANENT and now > row["expiry"],
    } for row in rows]
    return jsonify({"success": True, "keys": keys})


@app.route("/panel/delete", methods=["POST"])
def panel_delete():
    data = get_json()
    if not check_password(data.get("password"), PANEL_PASSWORD):
        return jsonify({"success": False, "error": "No autorizado"}), 403
    sb_delete(data.get("id"))
    return jsonify({"success": True})


@app.route("/panel/toggle", methods=["POST"])
def panel_toggle():
    data = get_json()
    if not check_password(data.get("password"), PANEL_PASSWORD):
        return jsonify({"success": False, "error": "No autorizado"}), 403
    rows = sb_get(f"id=eq.{data.get('id')}")
    if not rows:
        return jsonify({"success": False, "error": "No encontrado"}), 404
    new_active = 0 if rows[0]["active"] == 1 else 1
    sb_update(data.get("id"), {"active": new_active})
    return jsonify({"success": True, "active": new_active})


@app.route("/panel/change_user", methods=["POST"])
def panel_change_user():
    data = get_json()
    if not check_password(data.get("password"), PANEL_PASSWORD):
        return jsonify({"success": False, "error": "No autorizado"}), 403
    new_username = str(data.get("username", "")).strip().upper()
    if not new_username:
        return jsonify({"success": False, "error": "Usuario invalido"}), 400
    sb_update(data.get("id"), {"username": new_username})
    return jsonify({"success": True, "username": new_username})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
