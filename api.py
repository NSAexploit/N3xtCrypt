"""
API pour intégration tierce (exemple Flask)
"""
from flask import Flask, request, jsonify
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine
from core.config import ConfigManager
from core.audit import AuditLogger
import base64
import os
import json

app = Flask(__name__)

key_manager = KeyManager()
crypto = CryptoEngine()
config = ConfigManager().config
audit = AuditLogger()
API_TOKEN = os.environ.get('N3XTCRYPT_API_TOKEN', 'changeme')

def require_token(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token != API_TOKEN:
            return jsonify({'error': 'Unauthorized'}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/encrypt', methods=['POST'])
@require_token
def encrypt():
    req = request.get_json()
    key_id = req.get('key_id', 'default')
    data = base64.b64decode(req.get('data', ''))
    key = key_manager.load_key(key_id)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    result = crypto.encrypt(data, key, config)
    out = {
        'data': base64.b64encode(result['data']).decode(),
        'iv': result['iv'].hex(),
        'tag': result['tag'].hex(),
        'salt': result['salt'].hex(),
        'hmac': result['hmac'].hex()
    }
    audit.log_event(f'API encrypt for key {key_id}')
    return jsonify(out)

@app.route('/decrypt', methods=['POST'])
@require_token
def decrypt():
    req = request.get_json()
    key_id = req.get('key_id', 'default')
    key = key_manager.load_key(key_id)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    try:
        enc = {
            'data': base64.b64decode(req['data']),
            'iv': bytes.fromhex(req['iv']),
            'tag': bytes.fromhex(req['tag']),
            'salt': bytes.fromhex(req['salt']),
            'hmac': bytes.fromhex(req['hmac'])
        }
        decrypted = crypto.decrypt(enc, key, config)
    except Exception as e:
        audit.log_event(f'API decrypt error: {e}', level='error')
        return jsonify({'error': str(e)}), 400
    audit.log_event(f'API decrypt for key {key_id}')
    return jsonify({'decrypted': base64.b64encode(decrypted).decode()})

@app.route('/audit', methods=['GET'])
@require_token
def get_audit():
    with open('n3xtcrypt.log', 'r') as f:
        log = f.read()
    return jsonify({'log': log, 'integrity': audit.verify_log_integrity()})

if __name__ == '__main__':
    app.run(debug=True)
