import tkinter as tk
from tkinter import ttk, messagebox
import threading
import sys
import os

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from gui.server_window import ServerWindow
from gui.client_window import ClientWindow

class LauncherWindow:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        
        self.root.title("Kriptoloji Projesi - Ana Menü")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (500 // 2)
        self.root.geometry(f"600x500+{x}+{y}")
        
        style = ttk.Style()
        style.theme_use('clam')
        
        self.root.configure(bg='#f5f5f5')
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        main_frame = tk.Frame(self.root, bg='#f5f5f5', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = tk.Label(
            main_frame,
            text="🔐 Kriptoloji Projesi",
            font=('Arial', 24, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.pack(pady=(0, 10))
        
        subtitle_label = tk.Label(
            main_frame,
            text="Server/Client Şifreleme Sistemi",
            font=('Arial', 14),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        subtitle_label.pack(pady=(0, 30))
        
        description_text = 
        
        description_label = tk.Label(
            main_frame,
            text=description_text,
            font=('Arial', 11),
            bg='#f5f5f5',
            fg='#34495e',
            justify=tk.LEFT
        )
        description_label.pack(pady=(0, 30))
        
        button_frame = tk.Frame(main_frame, bg='#f5f5f5')
        button_frame.pack(pady=(0, 20))
        
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
        
        info_frame = tk.LabelFrame(
            main_frame,
            text="Kullanım Talimatları",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        info_frame.pack(fill=tk.X, pady=(20, 0))
        
        info_text = 
        
        info_label = tk.Label(
            info_frame,
            text=info_text,
            font=('Arial', 10),
            bg='#f5f5f5',
            fg='#34495e',
            justify=tk.LEFT
        )
        info_label.pack(padx=15, pady=10)
        
        footer_label = tk.Label(
            main_frame,
            text="Python + Tkinter + Socket tabanlı kriptoloji sistemi",
            font=('Arial', 9),
            bg='#f5f5f5',
            fg='#95a5a6'
        )
        footer_label.pack(side=tk.BOTTOM, pady=(20, 0))
        
    def start_server(self):
        try:
            server_window = tk.Toplevel(self.root)
            server_window.title("Kriptoloji Server")
            
            server_app = ServerWindow(server_window)
            
            self.root.withdraw()
            
            def on_server_close():
                self.root.deiconify()
                server_window.destroy()
            
            server_window.protocol("WM_DELETE_WINDOW", on_server_close)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Server başlatılamadı: {str(e)}")
    
    def start_client(self):
        try:
            client_window = tk.Toplevel(self.root)
            client_window.title("Kriptoloji Client")
            
            client_app = ClientWindow(client_window)
            
            self.root.withdraw()
            
            def on_client_close():
                self.root.deiconify()
                client_window.destroy()
            
            client_window.protocol("WM_DELETE_WINDOW", on_client_close)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Client başlatılamadı: {str(e)}")
    
    def on_closing(self):
        
        self.root.destroy()

def main():
    root = tk.Tk()
    app = LauncherWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
