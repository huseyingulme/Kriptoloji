import sys
import os
import argparse
from shared.utils import Logger


def start_server(host="localhost", port=12345):
    """Server'ı başlatır"""
    try:
        Logger.info("Server başlatılıyor...", "Main")
        from server.main import main as server_main
        
        # Server parametrelerini ayarla
        sys.argv = ["server", "--host", host, "--port", str(port)]
        server_main()
        
    except Exception as e:
        Logger.error(f"Server başlatma hatası: {str(e)}", "Main")
        print(f"Server başlatma hatası: {str(e)}")
        sys.exit(1)


def start_client():
    """Client'ı başlatır"""
    try:
        Logger.info("Client başlatılıyor...", "Main")
        from client.main import main as client_main
        client_main()
        
    except Exception as e:
        Logger.error(f"Client başlatma hatası: {str(e)}", "Main")
        print(f"Client başlatma hatası: {str(e)}")
        sys.exit(1)


def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(description="Kriptoloji Projesi - Şifreleme/Çözme Sistemi")
    parser.add_argument("mode", choices=["server", "client"], 
                       help="Çalıştırılacak mod: server veya client")
    parser.add_argument("--host", default="localhost", 
                       help="Server host adresi (varsayılan: localhost)")
    parser.add_argument("--port", type=int, default=12345, 
                       help="Server port numarası (varsayılan: 12345)")
    
    args = parser.parse_args()
    
    if args.mode == "server":
        start_server(args.host, args.port)
    elif args.mode == "client":
        start_client()
    else:
        print("Geçersiz mod. 'server' veya 'client' kullanın.")
        sys.exit(1)


if __name__ == "__main__":
    main()
