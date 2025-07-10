"""
Gestion de la configuration dynamique (JSON/YAML)
"""
import yaml
import json
import os

class ConfigManager:
    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self.config = {}
        if not os.path.exists(self.config_file):
            self.config = self.default_config()
            self.save_config()
        self.load_config()

    def default_config(self):
        return {
            'aes_mode': 'GCM',
            'bcrypt_cost': 100,
            'ascii': False,
            'plugin_encrypt': None
        }

    def load_config(self):
        if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        elif self.config_file.endswith('.json'):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)

    def save_config(self):
        if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
            with open(self.config_file, 'w') as f:
                yaml.safe_dump(self.config, f)
        elif self.config_file.endswith('.json'):
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
