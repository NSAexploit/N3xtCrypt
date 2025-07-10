"""
Interface graphique (GUI) pour N3xtCrypt
"""
from PyQt5 import QtWidgets, QtCore
import sys
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine
from core.io import FileIO, TextIO
from core.audit import AuditLogger
from core.config import ConfigManager
import base64
import json

class N3xtCryptGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.master_password = None
        self.key_manager = KeyManager(master_password=self.master_password)
        self.crypto = CryptoEngine()
        self.fileio = FileIO()
        self.textio = TextIO()
        self.audit = AuditLogger()
        self.config = ConfigManager().config
        self.init_ui()

    def ask_password(self):
        pw, ok = QtWidgets.QInputDialog.getText(self, 'Mot de passe maître', 'Entrez le mot de passe maître pour le stockage local chiffré :', QtWidgets.QLineEdit.Password)
        if ok and pw:
            self.master_password = pw
            self.key_manager.master_password = pw
            return pw
        return None

    def init_ui(self):
        self.setWindowTitle('N3xtCrypt')
        self.resize(600, 400)
        layout = QtWidgets.QVBoxLayout()
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.encrypt_tab(), 'Chiffrer')
        self.tabs.addTab(self.decrypt_tab(), 'Déchiffrer')
        self.tabs.addTab(self.keygen_tab(), 'Générer Clé')
        self.tabs.addTab(self.audit_tab(), 'Audit')
        layout.addWidget(self.tabs)
        self.setLayout(layout)
        self.show()

    def encrypt_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()
        self.enc_input = QtWidgets.QLineEdit()
        self.enc_file_btn = QtWidgets.QPushButton('Fichier...')
        self.enc_file_btn.clicked.connect(self.load_enc_file)
        self.enc_key = QtWidgets.QLineEdit('default')
        self.enc_output = QtWidgets.QTextEdit()
        self.enc_btn = QtWidgets.QPushButton('Chiffrer')
        self.enc_btn.clicked.connect(self.do_encrypt)
        layout.addRow('Texte ou fichier à chiffrer :', self.enc_input)
        layout.addRow('', self.enc_file_btn)
        layout.addRow('ID de la clé :', self.enc_key)
        layout.addRow(self.enc_btn)
        layout.addRow('Résultat (JSON) :', self.enc_output)
        tab.setLayout(layout)
        return tab

    def decrypt_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()
        self.dec_input = QtWidgets.QTextEdit()
        self.dec_key = QtWidgets.QLineEdit('default')
        self.dec_btn = QtWidgets.QPushButton('Déchiffrer')
        self.dec_btn.clicked.connect(self.do_decrypt)
        self.dec_output = QtWidgets.QTextEdit()
        layout.addRow('Entrée chiffrée (JSON) :', self.dec_input)
        layout.addRow('ID de la clé :', self.dec_key)
        layout.addRow(self.dec_btn)
        layout.addRow('Résultat (texte) :', self.dec_output)
        tab.setLayout(layout)
        return tab

    def keygen_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()
        self.keygen_id = QtWidgets.QLineEdit('default')
        self.keygen_btn = QtWidgets.QPushButton('Générer')
        self.keygen_btn.clicked.connect(self.do_keygen)
        self.keygen_status = QtWidgets.QLabel()
        layout.addRow('ID de la clé :', self.keygen_id)
        layout.addRow(self.keygen_btn)
        layout.addRow('Statut :', self.keygen_status)
        tab.setLayout(layout)
        return tab

    def audit_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        self.audit_text = QtWidgets.QTextEdit()
        self.audit_text.setReadOnly(True)
        self.audit_refresh = QtWidgets.QPushButton('Rafraîchir')
        self.audit_refresh.clicked.connect(self.load_audit)
        layout.addWidget(self.audit_text)
        layout.addWidget(self.audit_refresh)
        tab.setLayout(layout)
        return tab

    def load_enc_file(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Ouvrir un fichier', '', 'Tous les fichiers (*)')
        if fname:
            with open(fname, 'rb') as f:
                self.enc_input.setText(base64.b64encode(f.read()).decode())

    def do_encrypt(self):
        key_id = self.enc_key.text()
        key = self.key_manager.load_key(key_id, password=self.master_password)
        if not key:
            self.enc_output.setText('Clé introuvable.')
            return
        try:
            try:
                data = base64.b64decode(self.enc_input.text())
            except Exception:
                data = self.enc_input.text().encode()
            result = self.crypto.encrypt(data, key, self.config)
            out = {
                'data': base64.b64encode(result['data']).decode(),
                'iv': result['iv'].hex(),
                'tag': result['tag'].hex(),
                'salt': result['salt'].hex(),
                'hmac': result['hmac'].hex()
            }
            self.enc_output.setText(json.dumps(out, indent=2))
            self.audit.log_event(f'GUI encrypt for key {key_id}')
        except Exception as e:
            self.enc_output.setText(f'Erreur : {e}')

    def do_decrypt(self):
        key_id = self.dec_key.text()
        key = self.key_manager.load_key(key_id, password=self.master_password)
        if not key:
            self.dec_output.setText('Clé introuvable.')
            return
        try:
            enc = json.loads(self.dec_input.toPlainText())
            # Plus de clé 'iv', headers obfusqués
            if 'iv' in enc:
                self.dec_output.setText("Erreur : Ce format n'est plus supporté. Utilisez un JSON avec 'data' et 'headers' (obfuscation active).")
                return
            enc['data'] = enc['data'].encode() if isinstance(enc['data'], str) else enc['data']
            plaintext = self.crypto.decrypt(enc, key, self.config)
            try:
                self.dec_output.setText(plaintext.decode())
            except Exception:
                self.dec_output.setText(str(plaintext))
            self.audit.log_event(f'GUI decrypt for key {key_id}')
        except Exception as e:
            self.dec_output.setText(f'Erreur : {e}\nVérifiez que le format d\'entrée est bien celui généré par la dernière version du logiciel (data + headers obfusqués).')

    def do_keygen(self):
        key_id = self.keygen_id.text()
        if not self.master_password:
            pw = self.ask_password()
            if not pw:
                self.keygen_status.setText('Opération annulée : mot de passe requis.')
                return
        key = self.key_manager.generate_key()
        try:
            self.key_manager.store_key(key_id, key, password=self.master_password)
            self.keygen_status.setText(f'Clé générée et stockée : {key_id}')
            self.audit.log_event(f'GUI keygen {key_id}')
        except Exception as e:
            self.keygen_status.setText(f'Erreur : {e}')

    def load_audit(self):
        try:
            with open('n3xtcrypt.log', 'r') as f:
                log = f.read()
            integrity = 'OK' if self.audit.verify_log_integrity() else 'CORROMPU'
            self.audit_text.setText(log + f'\nIntégrité du log : {integrity}')
        except Exception as e:
            self.audit_text.setText(f'Erreur : {e}')

def main():
    app = QtWidgets.QApplication([])
    gui = N3xtCryptGUI()
    app.exec_()

if __name__ == '__main__':
    main()
