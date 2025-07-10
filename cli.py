"""
Interface CLI pour N3xtCrypt
"""
import argparse
import base64
import json
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine
from core.io import FileIO, TextIO
from core.audit import AuditLogger
from core.config import ConfigManager

def main():
    parser = argparse.ArgumentParser(description='N3xtCrypt CLI')
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'keygen', 'audit', 'export_csv', 'export_pdf'], help='Action à effectuer')
    parser.add_argument('--input', help='Fichier ou texte à traiter')
    parser.add_argument('--output', help='Fichier de sortie')
    parser.add_argument('--key', help='ID de la clé à utiliser')
    parser.add_argument('--config', help='Fichier de configuration')
    parser.add_argument('--password', help='Mot de passe maître pour la gestion des clés')
    parser.add_argument('--ascii', action='store_true', help='Activer l’encodage ASCII custom')
    parser.add_argument('--aes-mode', choices=['GCM', 'CBC'], default='GCM', help='Mode AES')
    parser.add_argument('--bcrypt-cost', type=int, default=12, help='Facteur de coût Bcrypt')
    args = parser.parse_args()

    config = ConfigManager(args.config).config if args.config else {
        'aes_mode': args.aes_mode,
        'bcrypt_cost': args.bcrypt_cost,
        'ascii': args.ascii
    }
    key_manager = KeyManager(master_password=args.password)
    crypto = CryptoEngine()
    fileio = FileIO()
    textio = TextIO()
    audit = AuditLogger()

    if args.action == 'keygen':
        key = key_manager.generate_key()
        key_id = args.key or 'default'
        key_manager.store_key(key_id, key, password=args.password)
        print(f'Clé générée et stockée avec l’ID : {key_id}')
        audit.log_event(f'Clé générée : {key_id}')
    elif args.action == 'encrypt':
        key = key_manager.load_key(args.key or 'default', password=args.password)
        if not key:
            print('Clé introuvable. Générez une clé d’abord.')
            return
        if args.input:
            data = fileio.read_file(args.input, binary=True)
        else:
            data = textio.read_text().encode()
        result = crypto.encrypt(data, key, config)
        # Nouveau format : data + headers (obfusqués)
        out = {
            'data': result['data'].decode() if isinstance(result['data'], bytes) else result['data'],
            'headers': result['headers']
        }
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(out, f, indent=2)
        else:
            print(json.dumps(out, indent=2))
        audit.log_event(f'Chiffrement effectué avec la clé {args.key}')
    elif args.action == 'decrypt':
        key = key_manager.load_key(args.key or 'default', password=args.password)
        if not key:
            print('Clé introuvable. Générez une clé d’abord.')
            return
        if args.input:
            with open(args.input, 'r') as f:
                enc = json.load(f)
        else:
            enc = json.loads(textio.read_text())
        # Nouveau format : data + headers (obfusqués)
        if 'iv' in enc:
            print("Erreur : Ce format n'est plus supporté. Utilisez un JSON avec 'data' et 'headers' (obfuscation active).")
            return
        enc['data'] = enc['data'].encode() if isinstance(enc['data'], str) else enc['data']
        try:
            decrypted = crypto.decrypt(enc, key, config)
        except Exception as e:
            print(f'Erreur de déchiffrement : {e}\nVérifiez que le format d\'entrée est bien celui généré par la dernière version du logiciel (data + headers obfusqués).')
            audit.log_event(f'Erreur de déchiffrement : {e}', level='error')
            return
        if args.output:
            fileio.write_file(args.output, decrypted, binary=True)
        else:
            textio.write_text(decrypted.decode(errors="ignore"))
        audit.log_event(f'Déchiffrement effectué avec la clé {args.key}')
    elif args.action == 'audit':
        print('Audit log :')
        with open('n3xtcrypt.log', 'r') as f:
            print(f.read())
        print('Vérification d’intégrité du log :')
        print('OK' if audit.verify_log_integrity() else 'CORROMPU')
    elif args.action == 'export_csv':
        audit.export_csv()
        print('Audit exporté en CSV.')
    elif args.action == 'export_pdf':
        audit.export_pdf()
        print('Audit exporté en PDF.')

if __name__ == '__main__':
    main()
