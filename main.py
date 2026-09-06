from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import time
import random
import string
import os
import sqlite3

app = Flask(__name__)
CORS(app)

SECRET = os.environ.get("SECRET_KEY", "MiClaveSecreta123")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "soybaby12071207")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "miguel_fk1_")

def get_db():
    conn = sqlite3.connect('keys.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        expiry INTEGER NOT NULL,
        expiry_readable TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        active INTEGER DEFAULT 1
    )''')
    conn.commit()
    conn.close()

init_db()

def simple_hash(text):
    combined = (SECRET + text).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()[:8].upper()

def random_part():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

@app.route('/')
def index():
    return 'Admin Key Server funcionando ✅'

@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    duration = int(data.get('duration', 3600))
    username = data.get('username', '').strip().upper()

    if not username:
        return jsonify({'success': False, 'error': 'El usuario es obligatorio'}), 400

    now = int(time.time())
    expiry = 9999999999 if duration == 0 else now + duration
    signature = simple_hash(str(expiry))
    key = f"ADMIN-{random_part()}-{expiry}-{signature}"
    expiry_readable = "Permanente" if duration == 0 else time.strftime('%d/%m/%Y %H:%M', time.localtime(expiry))

    conn = get_db()
    try:
        conn.execute('INSERT INTO keys (key, username, expiry, expiry_readable, created_at) VALUES (?, ?, ?, ?, ?)',
                     (key, username, expiry, expiry_readable, now))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500
    conn.close()

    return jsonify({'success': True, 'key': key, 'expiry': expiry_readable, 'username': username})

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    key = data.get('key', '').strip()
    username = data.get('username', '').strip().upper()

    parts = key.split('-')
    if len(parts) != 4 or parts[0] != 'ADMIN':
        return jsonify({'valid': False, 'reason': 'Key invalida'})

    expiry = parts[2]
    signature = parts[3]

    # Verificar firma basica
    expected_sig = simple_hash(expiry)
    if signature != expected_sig:
        return jsonify({'valid': False, 'reason': 'Key invalida'})

    # Verificar expiracion
    now = int(time.time())
    if int(expiry) != 9999999999 and now > int(expiry):
        return jsonify({'valid': False, 'reason': 'Key expirada'})

    # Buscar en base de datos
    conn = get_db()
    row = conn.execute('SELECT * FROM keys WHERE key = ? AND active = 1', (key,)).fetchone()
    conn.close()

    if not row:
        return jsonify({'valid': False, 'reason': 'Key desactivada o no existe'})

    # Verificar que el usuario coincide
    if row['username'] != username:
        return jsonify({'valid': False, 'reason': 'Usuario incorrecto'})

    # Tiempo restante
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

    return jsonify({'valid': True, 'reason': 'OK', 'time_left': time_left})

@app.route('/panel/keys', methods=['POST'])
def panel_keys():
    data = request.get_json()
    if data.get('password') != PANEL_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    conn = get_db()
    rows = conn.execute('SELECT * FROM keys ORDER BY created_at DESC').fetchall()
    conn.close()
    keys = []
    now = int(time.time())
    for row in rows:
        keys.append({
            'id': row['id'],
            'key': row['key'],
            'username': row['username'],
            'expiry_readable': row['expiry_readable'],
            'active': row['active'],
            'expired': row['expiry'] != 9999999999 and now > row['expiry']
        })
    return jsonify({'success': True, 'keys': keys})

@app.route('/panel/delete', methods=['POST'])
def panel_delete():
    data = request.get_json()
    if data.get('password') != PANEL_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    conn = get_db()
    conn.execute('DELETE FROM keys WHERE id = ?', (data.get('id'),))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/panel/toggle', methods=['POST'])
def panel_toggle():
    data = request.get_json()
    if data.get('password') != PANEL_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    conn = get_db()
    row = conn.execute('SELECT active FROM keys WHERE id = ?', (data.get('id'),)).fetchone()
    new_active = 0 if row['active'] == 1 else 1
    conn.execute('UPDATE keys SET active = ? WHERE id = ?', (new_active, data.get('id')))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'active': new_active})

@app.route('/panel/change_user', methods=['POST'])
def panel_change_user():
    data = request.get_json()
    if data.get('password') != PANEL_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403
    new_username = data.get('username', '').strip().upper()
    if not new_username:
        return jsonify({'success': False, 'error': 'Usuario invalido'}), 400
    conn = get_db()
    conn.execute('UPDATE keys SET username = ? WHERE id = ?', (new_username, data.get('id')))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'username': new_username})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
