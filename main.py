"""
Point d'entrée principal de N3xtCrypt
"""
import sys

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ['encrypt', 'decrypt', 'keygen', 'audit', 'export_csv', 'export_pdf']:
        import cli
        cli.main()
    elif len(sys.argv) > 1 and sys.argv[1] == 'gui':
        import gui
        gui.main()
    elif len(sys.argv) > 1 and sys.argv[1] == 'api':
        import api
    else:
        print('Usage: python main.py [encrypt|decrypt|keygen|audit|export_csv|export_pdf|gui|api]')
