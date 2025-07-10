"""
Moteur de chiffrement multi-couche configurable
"""

import base64
import base58
import base64 as b64
import base64 as b85
import os
import secrets
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2.low_level import hash_secret_raw, Type
import hashlib
import random

class CryptoEngine:
    def __init__(self):
        self.backend = default_backend()
        self.chacha_key_size = 32
        self.chacha_nonce_size = 12

    def encrypt(self, data, key, config=None):
        config = config or {}
        # 0. Compression
        compressed = zlib.compress(data)
        # 1. Padding aléatoire (8-32 octets)
        pad_len = random.randint(8, 32)
        pad = secrets.token_bytes(pad_len)
        padded = compressed + pad + pad_len.to_bytes(1, 'big')
        # 2. Argon2id KDF
        salt = os.urandom(32)
        derived_key = self.layer_argon2id_kdf(key, salt)
        # 3. AES-256-GCM
        iv = os.urandom(12)
        aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=self.backend)
        encryptor = aes_cipher.encryptor()
        aes_ct = encryptor.update(padded) + encryptor.finalize()
        aes_tag = encryptor.tag
        # 4. ChaCha20-Poly1305
        chacha_key = hashlib.sha3_256(derived_key).digest()
        chacha_nonce = os.urandom(self.chacha_nonce_size)
        chacha = aead.ChaCha20Poly1305(chacha_key)
        chacha_ct = chacha.encrypt(chacha_nonce, aes_ct, None)
        # 5. XOR dynamique
        xor_key = hashlib.sha3_256(salt + derived_key).digest()
        xor_data = self.layer_xor(chacha_ct, xor_key)
        # 6. Base64, Base85, Base58
        b64_data = base64.b64encode(xor_data)
        b85_data = base64.b85encode(b64_data)
        b58_data = base58.b58encode(b85_data)
        # 7. HMAC SHA3-512
        hmac_tag = self.layer_hmac_sha3(b58_data, derived_key)
        # 8. Obfuscation des headers (mélange)
        headers = [iv, aes_tag, salt, chacha_nonce, hmac_tag]
        random.shuffle(headers)
        return {
            'data': b58_data,
            'headers': [h.hex() for h in headers]
        }

    def decrypt(self, encrypted_dict, key, config=None):
        config = config or {}
        b58_data = encrypted_dict['data']
        headers = [bytes.fromhex(h) for h in encrypted_dict['headers']]
        # 1. Désobfuscation headers (essai toutes les combinaisons)
        from itertools import permutations
        for perm in permutations(headers):
            iv, aes_tag, salt, chacha_nonce, hmac_tag = perm
            try:
                # 2. Argon2id KDF
                derived_key = self.layer_argon2id_kdf(key, salt)
                # 3. HMAC SHA3-512
                if not self.layer_hmac_sha3_verify(b58_data, derived_key, hmac_tag):
                    continue
                # 4. Base58, Base85, Base64
                b85_data = base58.b58decode(b58_data)
                b64_data = base64.b85decode(b85_data)
                xor_data = base64.b64decode(b64_data)
                # 5. XOR dynamique
                xor_key = hashlib.sha3_256(salt + derived_key).digest()
                chacha_ct = self.layer_xor(xor_data, xor_key)
                # 6. ChaCha20-Poly1305
                chacha_key = hashlib.sha3_256(derived_key).digest()
                chacha = aead.ChaCha20Poly1305(chacha_key)
                aes_ct = chacha.decrypt(chacha_nonce, chacha_ct, None)
                # 7. AES-256-GCM
                aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, aes_tag), backend=self.backend)
                decryptor = aes_cipher.decryptor()
                padded = decryptor.update(aes_ct) + decryptor.finalize()
                # 8. Dépadding aléatoire
                pad_len = padded[-1]
                compressed = padded[:-pad_len-1]
                # 9. Décompression
                plaintext = zlib.decompress(compressed)
                return plaintext
            except Exception:
                continue
        raise ValueError('Impossible de désobfusquer les headers ou de déchiffrer les données.')

    def layer_argon2id_kdf(self, key, salt, mem_cost=256*1024, time_cost=8, parallelism=4):
        return hash_secret_raw(
            secret=key,
            salt=salt,
            time_cost=time_cost,
            memory_cost=mem_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID
        )

    def layer_xor(self, data, xor_key):
        return bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data)])

    def layer_hmac_sha3(self, data, key):
        h = hmac.HMAC(key, hashes.SHA3_512(), backend=self.backend)
        h.update(data)
        return h.finalize()

    def layer_hmac_sha3_verify(self, data, key, tag):
        h = hmac.HMAC(key, hashes.SHA3_512(), backend=self.backend)
        h.update(data)
        try:
            h.verify(tag)
            return True
        except Exception:
            return False
