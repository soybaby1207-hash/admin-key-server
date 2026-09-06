from flask import Flask, request, jsonify
import hashlib
import time
import random
import string
import os

app = Flask(__name__)

# Clave secreta - cámbiala en Railway en las variables de entorno
SECRET = os.environ.get("SECRET_KEY", "MiClaveSecreta123")
# Contraseña para generar keys - solo tú la sabes
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "MiPasswordAdmin456")

def simple_hash(text):
    combined = (SECRET + text).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()[:8].upper()

def random_part():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

# Generar una key
@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()

    # Verificar password de admin
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    duration = int(data.get('duration', 3600))
    username = data.get('username', 'ANY').upper()

    now = int(time.time())
    expiry = 9999999999 if duration == 0 else now + duration

    signature = simple_hash(str(expiry) + username)
    key = f"ADMIN-{random_part()}-{expiry}-{signature}"

    expiry_readable = "Permanente" if duration == 0 else time.strftime('%d/%m/%Y %H:%M', time.localtime(expiry))

    return jsonify({
        'success': True,
        'key': key,
        'expiry': expiry_readable,
        'username': username
    })

# Verificar una key (lo llama el juego de Roblox)
@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    key = data.get('key', '')
    username = data.get('username', '').upper()

    parts = key.split('-')
    if len(parts) != 4 or parts[0] != 'ADMIN':
        return jsonify({'valid': False, 'reason': 'Key invalida'})

    expiry = parts[2]
    signature = parts[3]

    # Comprobar expiración
    now = int(time.time())
    if int(expiry) != 9999999999 and now > int(expiry):
        return jsonify({'valid': False, 'reason': 'Key expirada'})

    # Verificar firma (ANY o nombre de usuario específico)
    sig_any = simple_hash(expiry + 'ANY')
    sig_user = simple_hash(expiry + username)

    if signature == sig_any or signature == sig_user:
        return jsonify({'valid': True, 'reason': 'OK'})

    return jsonify({'valid': False, 'reason': 'Key invalida'})

@app.route('/')
def index():
    return 'Admin Key Server funcionando ✅'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
