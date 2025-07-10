"""
Module d'entrée/sortie : gestion fichiers, texte, communications
"""

class FileIO:
    def read_file(self, path, binary=True):
        mode = 'rb' if binary else 'r'
        with open(path, mode) as f:
            return f.read()
    def write_file(self, path, data, binary=True):
        mode = 'wb' if binary else 'w'
        with open(path, mode) as f:
            f.write(data)

class TextIO:
    def read_text(self):
        return input('Entrée texte : ')
    def write_text(self, text):
        print(text)

class CommunicationIO:
    def send(self, data, destination):
        pass
    def receive(self, source):
        pass
