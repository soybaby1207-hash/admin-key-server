from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import hashlib
import time
import random
import string
import os
import requests

app = Flask(__name__)
CORS(app)

SECRET = os.environ.get("SECRET_KEY", "MiClaveSecreta123")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "soybaby12071207")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "miguel_fk1_")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

GENERATOR_HTML = open("generator.html").read() if os.path.exists("generator.html") else "<h1>No found</h1>"

def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

def sb_get(filters=""):
    r = requests.get(f"{SUPABASE_URL}/rest/v1/keys?{filters}&order=created_at.desc", headers=sb_headers())
    return r.json()

def sb_insert(data):
    r = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=sb_headers(), json=data)
    return r.json()

def sb_update(id, data):
    r = requests.patch(f"{SUPABASE_URL}/rest/v1/keys?id=eq.{id}", headers=sb_headers(), json=data)
    return r

def sb_delete(id):
    r = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?id=eq.{id}", headers=sb_headers())
    return r

def sb_find_key(key):
    r = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=sb_headers())
    data = r.json()
    return data[0] if data else None

def simple_hash(text):
    combined = (SECRET + text).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()[:8].upper()

def random_part():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=4))

@app.route("/")
def index():
    return "Admin Key Server funcionando ✅"

@app.route("/generator")
def generator():
    return GENERATOR_HTML

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    if data.get("password") != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "No autorizado"}), 403
    duration = int(data.get("duration", 3600))
    username = data.get("username", "").strip().upper()
    if not username:
        return jsonify({"success": False, "error": "El usuario es obligatorio"}), 400
    now = int(time.time())
    expiry = 9999999999 if duration == 0 else now + duration
    signature = simple_hash(str(expiry))
    key = f"ADMIN-{random_part()}-{expiry}-{signature}"
    expiry_readable = "Permanente" if duration == 0 else time.strftime("%d/%m/%Y %H:%M", time.localtime(expiry))
    result = sb_insert({"key": key, "username": username, "expiry": expiry, "expiry_readable": expiry_readable, "created_at": now, "active": 1})
    if isinstance(result, list) and len(result) > 0:
        return jsonify({"success": True, "key": key, "expiry": expiry_readable, "username": username})
    return jsonify({"success": False, "error": "Error guardando la key"}), 500

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    key = data.get("key", "").strip()
    username = data.get("username", "").strip().upper()
    parts = key.split("-")
    if len(parts) != 4 or parts[0] != "ADMIN":
        return jsonify({"valid": False, "reason": "Key invalida"})
    expiry = parts[2]
    signature = parts[3]
    if signature != simple_hash(expiry):
        return jsonify({"valid": False, "reason": "Key invalida"})
    now = int(time.time())
    if int(expiry) != 9999999999 and now > int(expiry):
        return jsonify({"valid": False, "reason": "Key expirada"})
    row = sb_find_key(key)
    if not row:
        return jsonify({"valid": False, "reason": "Key no existe"})
    if row["active"] != 1:
        return jsonify({"valid": False, "reason": "Key desactivada"})
    if row["username"] != username:
        return jsonify({"valid": False, "reason": "Usuario incorrecto"})
    expiry_int = int(expiry)
    if expiry_int == 9999999999:
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
    data = request.get_json()
    if data.get("password") != PANEL_PASSWORD:
        return jsonify({"success": False, "error": "No autorizado"}), 403
    rows = sb_get()
    now = int(time.time())
    keys = []
    for row in rows:
        keys.append({"id": row["id"], "key": row["key"], "username": row["username"], "expiry_readable": row["expiry_readable"], "active": row["active"], "expired": row["expiry"] != 9999999999 and now > row["expiry"]})
    return jsonify({"success": True, "keys": keys})

@app.route("/panel/delete", methods=["POST"])
def panel_delete():
    data = request.get_json()
    if data.get("password") != PANEL_PASSWORD:
        return jsonify({"success": False, "error": "No autorizado"}), 403
    sb_delete(data.get("id"))
    return jsonify({"success": True})

@app.route("/panel/toggle", methods=["POST"])
def panel_toggle():
    data = request.get_json()
    if data.get("password") != PANEL_PASSWORD:
        return jsonify({"success": False, "error": "No autorizado"}), 403
    rows = sb_get(f"id=eq.{data.get('id')}")
    if not rows:
        return jsonify({"success": False, "error": "No encontrado"}), 404
    new_active = 0 if rows[0]["active"] == 1 else 1
    sb_update(data.get("id"), {"active": new_active})
    return jsonify({"success": True, "active": new_active})

@app.route("/panel/change_user", methods=["POST"])
def panel_change_user():
    data = request.get_json()
    if data.get("password") != PANEL_PASSWORD:
        return jsonify({"success": False, "error": "No autorizado"}), 403
    new_username = data.get("username", "").strip().upper()
    if not new_username:
        return jsonify({"success": False, "error": "Usuario invalido"}), 400
    sb_update(data.get("id"), {"username": new_username})
    return jsonify({"success": True, "username": new_username})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
