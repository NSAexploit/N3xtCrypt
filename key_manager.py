"""
Gestion centralisée des clés : génération, stockage, rotation, permissions
"""

import os
import keyring
import secrets
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta
import keyring.errors

class KeyManager:
    def __init__(self, keyfile='n3xtcrypt.keys', master_password=None, storage_mode=None):
        self.keyfile = keyfile
        self.master_password = master_password or os.environ.get('N3XTCRYPT_MASTER')
        self.backend = default_backend()
        self.keys = self._load_keys()
        self.keyring_available = self._check_keyring()
        self.storage_mode = storage_mode or ('keyring' if self.keyring_available else 'local')
        if not self.keyring_available and storage_mode == 'keyring':
            print('[!] Keyring non disponible, fallback sur stockage local chiffré.')

    def _check_keyring(self):
        try:
            keyring.get_keyring().get_password('n3xtcrypt', '__test__')
            return True
        except keyring.errors.NoKeyringError:
            return False
        except Exception:
            return True  # keyring existe mais pas de mot de passe

    def generate_key(self, length=32):
        return secrets.token_bytes(length)

    def store_key(self, key_id, key, password=None, expire_days=365):
        if self.storage_mode == 'keyring' and self.keyring_available:
            try:
                keyring.set_password('n3xtcrypt', key_id, key.hex())
            except Exception:
                print('[!] Erreur keyring, fallback sur stockage local chiffré.')
                self.storage_mode = 'local'
        if self.storage_mode == 'local':
            pw = password or self.master_password
            if not pw:
                raise ValueError("Aucun mot de passe maître fourni pour le stockage local chiffré. Veuillez relancer avec --password ou définir N3XTCRYPT_MASTER.")
            self.keys[key_id] = {
                'key': self._encrypt_key(key, pw),
                'created': datetime.utcnow().isoformat(),
                'expires': (datetime.utcnow() + timedelta(days=expire_days)).isoformat(),
                'permissions': {'owner': 'admin', 'users': []}
            }
            self._save_keys()

    def load_key(self, key_id, password=None):
        if self.storage_mode == 'keyring' and self.keyring_available:
            try:
                key_hex = keyring.get_password('n3xtcrypt', key_id)
                if key_hex:
                    return bytes.fromhex(key_hex)
            except Exception:
                print('[!] Erreur keyring, fallback sur stockage local chiffré.')
                self.storage_mode = 'local'
        if self.storage_mode == 'local':
            pw = password or self.master_password
            if not pw:
                raise ValueError("Aucun mot de passe maître fourni pour le stockage local chiffré. Veuillez relancer avec --password ou définir N3XTCRYPT_MASTER.")
            if key_id in self.keys:
                enc = self.keys[key_id]['key']
                return self._decrypt_key(enc, pw)
        return None

    def rotate_key(self, key_id, password=None):
        new_key = self.generate_key()
        self.store_key(key_id, new_key, password=password)
        return new_key

    def set_permissions(self, key_id, user, permissions):
        if key_id in self.keys:
            self.keys[key_id]['permissions'][user] = permissions
            self._save_keys()

    def _encrypt_key(self, key, password):
        if not password:
            raise ValueError("Aucun mot de passe maître fourni pour le stockage local chiffré.")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        enc_key = kdf.derive(password.encode())
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(key) + encryptor.finalize()
        return {
            'salt': salt.hex(),
            'iv': iv.hex(),
            'ct': ct.hex(),
            'tag': encryptor.tag.hex()
        }

    def _decrypt_key(self, enc, password):
        if not password:
            raise ValueError("Aucun mot de passe maître fourni pour le stockage local chiffré.")
        salt = bytes.fromhex(enc['salt'])
        iv = bytes.fromhex(enc['iv'])
        ct = bytes.fromhex(enc['ct'])
        tag = bytes.fromhex(enc['tag'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        dec_key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(dec_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def _load_keys(self):
        if not os.path.exists(self.keyfile):
            return {}
        with open(self.keyfile, 'r') as f:
            return json.load(f)

    def _save_keys(self):
        with open(self.keyfile, 'w') as f:
            json.dump(self.keys, f, indent=2)
