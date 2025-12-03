import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.gui.MainWindow import MainWindow
from shared.utils import Logger


def main():
    try:
        Logger.info("Client uygulaması başlatılıyor...", "Client")
        
        app = MainWindow()
        app.run()
        
    except Exception as e:
        Logger.error(f"Client başlatma hatası: {str(e)}", "Client")
        print(f"Hata: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

