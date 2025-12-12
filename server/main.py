import sys
import os
import signal
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.network.Server import Server
from server.processing.ProcessingManager import ProcessingManager
from algorithms.KeyDistributionManager import KeyDistributionManager
from shared.utils import Logger

class ServerApplication:

    def __init__(self, host="localhost", port=12345, use_gui=True):
        self.host = host
        self.port = port
        self.server = None
        self.processing_manager = None
        self.key_manager = None
        self.running = False
        self.use_gui = use_gui

    def start(self):
        try:
            Logger.info("Server uygulaması başlatılıyor...", "ServerApp")

            self.processing_manager = ProcessingManager()
            self.key_manager = KeyDistributionManager()

            self.server = Server(self.host, self.port)
            self.server.set_processing_callback(self.processing_manager.process_request)
            self.server.set_key_manager(self.key_manager)

            if not self.use_gui:
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)

            self.running = True
            Logger.info(f"Server başlatıldı: {self.host}:{self.port}", "ServerApp")
            
            if not self.use_gui:
                Logger.info("Çıkmak için Ctrl+C tuşlarına basın", "ServerApp")

            self.server.start()

        except KeyboardInterrupt:
            Logger.info("Kullanıcı tarafından durduruldu", "ServerApp")
        except Exception as e:
            Logger.error(f"Server başlatma hatası: {str(e)}", "ServerApp")
            raise
        finally:
            self.stop()

    def stop(self):
        if self.running:
            Logger.info("Server durduruluyor...", "ServerApp")
            self.running = False

            if self.server:
                self.server.stop()

            Logger.info("Server durduruldu", "ServerApp")

    def _signal_handler(self, signum, frame):
        Logger.info(f"Signal alındı: {signum}", "ServerApp")
        self.stop()
        sys.exit(0)

def main():
    try:
        import argparse

        parser = argparse.ArgumentParser(description="Kriptoloji Server")
        parser.add_argument("--host", default="localhost", help="Server host adresi")
        parser.add_argument("--port", type=int, default=12345, help="Server port numarası")
        parser.add_argument("--no-gui", action="store_true", help="GUI olmadan çalıştır (sadece konsol)")

        args = parser.parse_args()

        # GUI kullan
        if not args.no_gui:
            try:
                from server.gui.ServerWindow import ServerWindow
                app = ServerWindow(args.host, args.port)
                app.run()
            except ImportError as e:
                Logger.warning(f"GUI yüklenemedi: {str(e)}, konsol moduna geçiliyor", "ServerApp")
                app = ServerApplication(args.host, args.port, use_gui=False)
                app.start()
        else:
            # Konsol modu
            app = ServerApplication(args.host, args.port, use_gui=False)
            app.start()

    except Exception as e:
        Logger.error(f"Server başlatma hatası: {str(e)}", "ServerApp")
        print(f"Hata: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
