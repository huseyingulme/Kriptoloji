import sys
import os
<<<<<<< HEAD
import tkinter as tk
from tkinter import messagebox

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from launcher import LauncherWindow
except ImportError as e:
    print(f"HATA - Launcher modulu yuklenemedi: {e}")
    print("Lutfen tum gerekli dosyalarin mevcut oldugundan emin olun.")
    sys.exit(1)


class KriptolojiApp:    
    def __init__(self):
        self.root = None
        self.main_window = None
        
    def check_dependencies(self):
        required_modules = [
            'tkinter',
            'threading',
            'os',
            'sys'
        ]
=======
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
>>>>>>> 06cbc65995ce6f48cc5058a702e20007d0341073
        
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
        
<<<<<<< HEAD
    def check_project_structure(self):
        required_dirs = [
            'algorithms',
            'utils', 
            'gui'
        ]
        
        required_files = [
            'algorithms/algorithm_manager.py',
            'utils/encryption_service.py',
            'gui/server_window.py',
            'gui/client_window.py',
            'launcher.py'
        ]
        
        missing_items = []
        
        for directory in required_dirs:
            if not os.path.exists(directory):
                missing_items.append(f"Dizin: {directory}")
                
        for file_path in required_files:
            if not os.path.exists(file_path):
                missing_items.append(f"Dosya: {file_path}")
                
        if missing_items:
            error_msg = "Eksik proje dosyalari:\n" + "\n".join(missing_items)
            print(f"HATA - {error_msg}")
            return False
            
        return True
        
    def show_splash_screen(self):
        splash = tk.Tk()
        splash.title("Kriptoloji Projesi")
        splash.geometry("400x300")
        splash.resizable(False, False)
        
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() // 2) - (400 // 2)
        y = (splash.winfo_screenheight() // 2) - (300 // 2)
        splash.geometry(f"400x300+{x}+{y}")
        
        splash.configure(bg='#667eea')
        
        title_label = tk.Label(
            splash,
            text="🔐 Kriptoloji Projesi",
            font=('Arial', 24, 'bold'),
            fg='white',
            bg='#667eea'
        )
        title_label.pack(pady=50)
        
        subtitle_label = tk.Label(
            splash,
            text="Server/Client Şifreleme Sistemi",
            font=('Arial', 12),
            fg='white',
            bg='#667eea'
        )
        subtitle_label.pack(pady=10)
        
        loading_label = tk.Label(
            splash,
            text="Yükleniyor...",
            font=('Arial', 10),
            fg='white',
            bg='#667eea'
        )
        loading_label.pack(pady=20)
        
        progress_frame = tk.Frame(splash, bg='#667eea')
        progress_frame.pack(pady=20)
        
        progress_bar = tk.Frame(progress_frame, bg='white', width=300, height=4)
        progress_bar.pack()
        
        splash.update()
        
        return splash
        
    def run(self):
        print("Kriptoloji Projesi Baslatiliyor...")
        print("=" * 50)
        
        if not self.check_dependencies():
            input("Devam etmek için Enter tuşuna basın...")
            return False
            
        if not self.check_project_structure():
            input("Devam etmek için Enter tuşuna basın...")
            return False
            
        splash = self.show_splash_screen()
        
        try:
            print("OK - Bagimliliklar kontrol edildi")
            print("OK - Proje yapisi dogrulandi")
            print("Ana uygulama baslatiliyor...")
            
            splash.after(2000, splash.destroy)
            
            self.root = tk.Tk()
            self.main_window = LauncherWindow(self.root)
            
            print("OK - Uygulama basariyla baslatildi!")
            print("GUI arayuzu acildi")
            print("-" * 50)
            
            self.root.mainloop()
            
            return True
            
        except Exception as e:
            print(f"HATA - Uygulama baslatma hatasi: {e}")
            
            try:
                splash.destroy()
            except:
                pass
                
            messagebox.showerror(
                "Başlatma Hatası",
                f"Uygulama başlatılamadı:\n{str(e)}"
            )
            
            return False
            
    def cleanup(self):
        if self.root:
            try:
                self.root.destroy()
            except:
                pass


def main():
    app = KriptolojiApp()
=======
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
>>>>>>> 06cbc65995ce6f48cc5058a702e20007d0341073
    
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
