"""
Module d'audit et journalisation
"""
import logging
import hashlib
import hmac as pyhmac
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class AuditLogger:
    def __init__(self, logfile='n3xtcrypt.log', hmac_key=b'supersecretkey'):
        self.logger = logging.getLogger('N3xtCrypt')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(logfile)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logfile = logfile
        self.hmac_key = hmac_key

    def log_event(self, event, level='info'):
        if level == 'info':
            self.logger.info(event)
        elif level == 'warning':
            self.logger.warning(event)
        elif level == 'error':
            self.logger.error(event)
        self._update_hmac()

    def _update_hmac(self):
        with open(self.logfile, 'rb') as f:
            content = f.read()
        mac = pyhmac.new(self.hmac_key, content, hashlib.sha256).hexdigest()
        with open(self.logfile + '.hmac', 'w') as f:
            f.write(mac)

    def verify_log_integrity(self):
        with open(self.logfile, 'rb') as f:
            content = f.read()
        with open(self.logfile + '.hmac', 'r') as f:
            mac = f.read()
        expected = pyhmac.new(self.hmac_key, content, hashlib.sha256).hexdigest()
        return mac == expected

    def export_csv(self, csvfile='n3xtcrypt_audit.csv'):
        with open(self.logfile, 'r') as f, open(csvfile, 'w', newline='') as out:
            writer = csv.writer(out)
            writer.writerow(['timestamp', 'level', 'message'])
            for line in f:
                parts = line.strip().split(' ', 2)
                if len(parts) == 3:
                    writer.writerow(parts)

    def export_pdf(self, pdffile='n3xtcrypt_audit.pdf'):
        c = canvas.Canvas(pdffile, pagesize=letter)
        width, height = letter
        y = height - 40
        with open(self.logfile, 'r') as f:
            for line in f:
                c.drawString(40, y, line.strip())
                y -= 15
                if y < 40:
                    c.showPage()
                    y = height - 40
        c.save()
