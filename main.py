#!/usr/bin/env python3
"""
🔐 Kriptoloji Projesi - Ana Uygulama
Server/Client tabanlı şifreleme ve çözme uygulaması
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Proje kök dizinini path'e ekle
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from launcher import LauncherWindow
except ImportError as e:
    print(f"HATA - Launcher modulu yuklenemedi: {e}")
    print("Lutfen tum gerekli dosyalarin mevcut oldugundan emin olun.")
    sys.exit(1)


class KriptolojiApp:
    """Ana uygulama sınıfı"""
    
    def __init__(self):
        self.root = None
        self.main_window = None
        
    def check_dependencies(self):
        """Gerekli bağımlılıkları kontrol et"""
        required_modules = [
            'tkinter',
            'threading',
            'os',
            'sys'
        ]
        
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
                
        if missing_modules:
            error_msg = f"Eksik moduller: {', '.join(missing_modules)}"
            print(f"HATA - {error_msg}")
            return False
            
        return True
        
    def check_project_structure(self):
        """Proje yapısını kontrol et"""
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
        """Başlangıç ekranı göster"""
        splash = tk.Tk()
        splash.title("Kriptoloji Projesi")
        splash.geometry("400x300")
        splash.resizable(False, False)
        
        # Pencereyi ortala
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() // 2) - (400 // 2)
        y = (splash.winfo_screenheight() // 2) - (300 // 2)
        splash.geometry(f"400x300+{x}+{y}")
        
        # Arka plan
        splash.configure(bg='#667eea')
        
        # Başlık
        title_label = tk.Label(
            splash,
            text="🔐 Kriptoloji Projesi",
            font=('Arial', 24, 'bold'),
            fg='white',
            bg='#667eea'
        )
        title_label.pack(pady=50)
        
        # Alt başlık
        subtitle_label = tk.Label(
            splash,
            text="Server/Client Şifreleme Sistemi",
            font=('Arial', 12),
            fg='white',
            bg='#667eea'
        )
        subtitle_label.pack(pady=10)
        
        # Yükleme mesajı
        loading_label = tk.Label(
            splash,
            text="Yükleniyor...",
            font=('Arial', 10),
            fg='white',
            bg='#667eea'
        )
        loading_label.pack(pady=20)
        
        # Progress bar
        progress_frame = tk.Frame(splash, bg='#667eea')
        progress_frame.pack(pady=20)
        
        progress_bar = tk.Frame(progress_frame, bg='white', width=300, height=4)
        progress_bar.pack()
        
        # Güncelleme
        splash.update()
        
        return splash
        
    def run(self):
        """Uygulamayı çalıştır"""
        print("Kriptoloji Projesi Baslatiliyor...")
        print("=" * 50)
        
        # Bağımlılıkları kontrol et
        if not self.check_dependencies():
            input("Devam etmek için Enter tuşuna basın...")
            return False
            
        # Proje yapısını kontrol et
        if not self.check_project_structure():
            input("Devam etmek için Enter tuşuna basın...")
            return False
            
        # Splash screen göster
        splash = self.show_splash_screen()
        
        try:
            # Ana pencereyi oluştur
            print("OK - Bagimliliklar kontrol edildi")
            print("OK - Proje yapisi dogrulandi")
            print("Ana uygulama baslatiliyor...")
            
            # Splash'i kapat
            splash.after(2000, splash.destroy)
            
            # Ana pencereyi oluştur
            self.root = tk.Tk()
            self.main_window = LauncherWindow(self.root)
            
            print("OK - Uygulama basariyla baslatildi!")
            print("GUI arayuzu acildi")
            print("-" * 50)
            
            # Ana döngüyü başlat
            self.root.mainloop()
            
            return True
            
        except Exception as e:
            print(f"HATA - Uygulama baslatma hatasi: {e}")
            
            # Splash'i kapat
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
        """Temizlik işlemleri"""
        if self.root:
            try:
                self.root.destroy()
            except:
                pass


def main():
    """Ana fonksiyon"""
    app = KriptolojiApp()
    
    try:
        success = app.run()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\nUygulama kullanici tarafindan durduruldu.")
        return 0
    except Exception as e:
        print(f"HATA - Beklenmeyen hata: {e}")
        return 1
    finally:
        app.cleanup()


if __name__ == "__main__":
    sys.exit(main())
