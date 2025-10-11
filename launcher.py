"""
Kriptoloji Projesi - Launcher
Ana uygulama başlatıcısı
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import sys
import os

# Proje kök dizinini path'e ekle
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from gui.server_window import ServerWindow
from gui.client_window import ClientWindow


class LauncherWindow:
    """
    Ana başlatıcı pencere
    Server veya Client seçimi yapılır
    """
    
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Pencere ayarlarını yap"""
        self.root.title("Kriptoloji Projesi - Ana Menü")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        # Pencereyi ortala
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (500 // 2)
        self.root.geometry(f"600x500+{x}+{y}")
        
        # Basit tema
        style = ttk.Style()
        style.theme_use('clam')
        
        # Pencere arka planı
        self.root.configure(bg='#f5f5f5')
        
        # Pencere kapatma olayı
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        """Widget'ları oluştur"""
        # Ana container
        main_frame = tk.Frame(self.root, bg='#f5f5f5', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_label = tk.Label(
            main_frame,
            text="🔐 Kriptoloji Projesi",
            font=('Arial', 24, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.pack(pady=(0, 10))
        
        # Alt başlık
        subtitle_label = tk.Label(
            main_frame,
            text="Server/Client Şifreleme Sistemi",
            font=('Arial', 14),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Açıklama
        description_text = """
Bu proje, güvenli veri alışverişi için tasarlanmış bir kriptoloji sistemidir.

Özellikler:
• 5 farklı şifreleme algoritması (Caesar, Vigenere, Affine, Substitution, Rail Fence)
• Server-Client tabanlı güvenli iletişim
• Dosya ve metin şifreleme/çözme
• Kullanıcı dostu arayüz
• Otomatik dosya yönetimi
        """
        
        description_label = tk.Label(
            main_frame,
            text=description_text,
            font=('Arial', 11),
            bg='#f5f5f5',
            fg='#34495e',
            justify=tk.LEFT
        )
        description_label.pack(pady=(0, 30))
        
        # Seçim butonları
        button_frame = tk.Frame(main_frame, bg='#f5f5f5')
        button_frame.pack(pady=(0, 20))
        
        # Server butonu
        server_button = tk.Button(
            button_frame,
            text="🖥️ Server Başlat",
            command=self.start_server,
            font=('Arial', 14, 'bold'),
            bg='#3498db',
            fg='white',
            relief=tk.FLAT,
            padx=30,
            pady=15,
            width=20
        )
        server_button.pack(side=tk.LEFT, padx=(0, 20))
        
        # Client butonu
        client_button = tk.Button(
            button_frame,
            text="💻 Client Başlat",
            command=self.start_client,
            font=('Arial', 14, 'bold'),
            bg='#e74c3c',
            fg='white',
            relief=tk.FLAT,
            padx=30,
            pady=15,
            width=20
        )
        client_button.pack(side=tk.LEFT)
        
        # Bilgi paneli
        info_frame = tk.LabelFrame(
            main_frame,
            text="Kullanım Talimatları",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        info_frame.pack(fill=tk.X, pady=(20, 0))
        
        info_text = """
1. Önce "Server Başlat" butonuna tıklayarak server'ı çalıştırın
2. Sonra "Client Başlat" butonuna tıklayarak client'ı açın
3. Client'ta server'a bağlanın (varsayılan: 127.0.0.1:8080)
4. Şifreleme/çözme işlemlerinizi gerçekleştirin
        """
        
        info_label = tk.Label(
            info_frame,
            text=info_text,
            font=('Arial', 10),
            bg='#f5f5f5',
            fg='#34495e',
            justify=tk.LEFT
        )
        info_label.pack(padx=15, pady=10)
        
        # Alt bilgi
        footer_label = tk.Label(
            main_frame,
            text="Python + Tkinter + Socket tabanlı kriptoloji sistemi",
            font=('Arial', 9),
            bg='#f5f5f5',
            fg='#95a5a6'
        )
        footer_label.pack(side=tk.BOTTOM, pady=(20, 0))
        
    def start_server(self):
        """Server'ı başlat"""
        try:
            # Yeni pencere oluştur
            server_window = tk.Toplevel(self.root)
            server_window.title("Kriptoloji Server")
            
            # Server arayüzünü başlat
            server_app = ServerWindow(server_window)
            
            # Ana pencereyi gizle
            self.root.withdraw()
            
            # Server penceresi kapatıldığında ana pencereyi göster
            def on_server_close():
                self.root.deiconify()
                server_window.destroy()
            
            server_window.protocol("WM_DELETE_WINDOW", on_server_close)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Server başlatılamadı: {str(e)}")
    
    def start_client(self):
        """Client'ı başlat"""
        try:
            # Yeni pencere oluştur
            client_window = tk.Toplevel(self.root)
            client_window.title("Kriptoloji Client")
            
            # Client arayüzünü başlat
            client_app = ClientWindow(client_window)
            
            # Ana pencereyi gizle
            self.root.withdraw()
            
            # Client penceresi kapatıldığında ana pencereyi göster
            def on_client_close():
                self.root.deiconify()
                client_window.destroy()
            
            client_window.protocol("WM_DELETE_WINDOW", on_client_close)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Client başlatılamadı: {str(e)}")
    
    def on_closing(self):
        """Pencere kapatılırken temizlik"""
        self.root.destroy()


def main():
    """Ana fonksiyon"""
    root = tk.Tk()
    app = LauncherWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
