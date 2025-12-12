import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server.network.Server import Server
from server.processing.ProcessingManager import ProcessingManager
from algorithms.KeyDistributionManager import KeyDistributionManager
from shared.utils import Logger


class ServerWindow:
    """Server için GUI arayüzü"""

    def __init__(self, host="localhost", port=12345):
        self.root = tk.Tk()
        self.root.title("Kriptoloji Server - Şifreleme Sunucusu")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        self.host = host
        self.port = port
        self.server = None
        self.processing_manager = None
        self.key_manager = None
        self.running = False
        self.client_count = 0
        self.request_count = 0

        self._create_widgets()
        self._setup_logging()

    def _create_widgets(self):
        """GUI bileşenlerini oluşturur"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Başlık
        title_label = ttk.Label(main_frame, text="Kriptoloji Server", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 20))

        # Durum bilgisi frame
        status_frame = ttk.LabelFrame(main_frame, text="Server Durumu", padding="10")
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Durum:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.status_label = ttk.Label(status_frame, text="Durduruldu", foreground="red")
        self.status_label.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Host:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.host_label = ttk.Label(status_frame, text=f"{self.host}:{self.port}")
        self.host_label.grid(row=1, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Bağlı Client:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        self.client_count_label = ttk.Label(status_frame, text="0")
        self.client_count_label.grid(row=2, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Toplam İstek:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10))
        self.request_count_label = ttk.Label(status_frame, text="0")
        self.request_count_label.grid(row=3, column=1, sticky=tk.W)

        # Kontrol butonları
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.start_button = ttk.Button(button_frame, text="Server'ı Başlat", 
                                      command=self._start_server)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_button = ttk.Button(button_frame, text="Server'ı Durdur", 
                                     command=self._stop_server, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(button_frame, text="Temizle", command=self._clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Çıkış", command=self._on_closing).pack(side=tk.RIGHT)

        # Log alanı
        log_frame = ttk.LabelFrame(main_frame, text="Server Logları", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED,
                                                 wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def _setup_logging(self):
        """Logger'a GUI handler ekler"""
        class GUIHandler:
            def __init__(self, text_widget):
                self.text_widget = text_widget

            def write(self, message):
                if message.strip():
                    self.text_widget.config(state=tk.NORMAL)
                    self.text_widget.insert(tk.END, message)
                    self.text_widget.see(tk.END)
                    self.text_widget.config(state=tk.DISABLED)

        # Logger'ı GUI'ye yönlendir (basit bir yaklaşım)
        pass

    def _log_message(self, message, level="INFO"):
        """Log mesajını GUI'ye ekler"""
        self.log_text.config(state=tk.NORMAL)
        color = {
            "INFO": "black",
            "WARNING": "orange",
            "ERROR": "red",
            "SUCCESS": "green"
        }.get(level, "black")
        
        self.log_text.insert(tk.END, f"[{level}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _start_server(self):
        """Server'ı başlatır"""
        def start_thread():
            try:
                self.root.after(0, lambda: self._log_message("Server başlatılıyor...", "INFO"))
                
                self.processing_manager = ProcessingManager()
                self.key_manager = KeyDistributionManager()

                self.server = Server(self.host, self.port)
                self.server.set_processing_callback(self.processing_manager.process_request)
                self.server.set_key_manager(self.key_manager)
                self.server.set_operation_callback(self._on_operation_event)

                # Server'ı thread'de başlat
                self.running = True
                self.root.after(0, lambda: self.status_label.config(text="Çalışıyor", foreground="green"))
                self.root.after(0, lambda: self.start_button.config(state="disabled"))
                self.root.after(0, lambda: self.stop_button.config(state="normal"))
                self.root.after(0, lambda: self._log_message(f"Server başlatıldı: {self.host}:{self.port}", "SUCCESS"))
                
                # İstatistik güncelleme timer'ını başlat
                self.root.after(1000, self._update_stats_periodic)

                # Server'ı başlat (blocking call - thread'de çalışır)
                self.server.start()

            except Exception as e:
                self.root.after(0, lambda: self._log_message(f"Server başlatma hatası: {str(e)}", "ERROR"))
                self.root.after(0, lambda: messagebox.showerror("Hata", f"Server başlatılamadı:\n{str(e)}"))
                self.root.after(0, lambda: self.status_label.config(text="Hata", foreground="red"))
                self.root.after(0, lambda: self.start_button.config(state="normal"))
                self.root.after(0, lambda: self.stop_button.config(state="disabled"))
                self.running = False

        threading.Thread(target=start_thread, daemon=True).start()

    def _stop_server(self):
        """Server'ı durdurur"""
        try:
            self._log_message("Server durduruluyor...", "INFO")
            self.running = False

            if self.server:
                self.server.stop()
                self.server = None

            self.status_label.config(text="Durduruldu", foreground="red")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.client_count = 0
            self.request_count = 0
            self._update_stats()
            self._log_message("Server durduruldu", "INFO")

        except Exception as e:
            self._log_message(f"Server durdurma hatası: {str(e)}", "ERROR")
            messagebox.showerror("Hata", f"Server durdurulamadı:\n{str(e)}")

    def _update_stats(self):
        """İstatistikleri günceller"""
        if self.server and hasattr(self.server, 'clients'):
            self.client_count = len(self.server.clients)
        self.client_count_label.config(text=str(self.client_count))
        self.request_count_label.config(text=str(self.request_count))
    
    def _update_stats_periodic(self):
        """İstatistikleri periyodik olarak günceller"""
        if self.running:
            self._update_stats()
            self.root.after(2000, self._update_stats_periodic)  # Her 2 saniyede bir güncelle
    
    def _on_operation_event(self, event_data):
        """İşlem olaylarını işler ve GUI'ye ekler"""
        def update_gui():
            try:
                event_type = event_data.get('type', 'unknown')
                client = event_data.get('client', 'Unknown')
                operation = event_data.get('operation', '')
                algorithm = event_data.get('algorithm', '')
                
                if event_type == 'operation_start':
                    self._log_message(f"📥 İşlem başladı: {client} → {operation.upper()} ({algorithm})", "INFO")
                    self.request_count += 1
                    self._update_stats()
                elif event_type == 'operation_success':
                    data_size = event_data.get('data_size', 0)
                    result_size = event_data.get('result_size', 0)
                    self._log_message(f"✅ İşlem tamamlandı: {client} → {operation.upper()} ({algorithm}) - Veri: {data_size}B → {result_size}B", "SUCCESS")
                elif event_type == 'operation_error':
                    error = event_data.get('error', 'Bilinmeyen hata')
                    self._log_message(f"❌ İşlem hatası: {client} → {operation.upper()} ({algorithm}) - {error}", "ERROR")
            except Exception as e:
                pass  # GUI güncelleme hatası sessizce geç
        
        self.root.after(0, update_gui)

    def _clear_logs(self):
        """Log alanını temizler"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _on_closing(self):
        """Uygulama kapatılırken"""
        if self.running:
            if messagebox.askyesno("Çıkış", "Server çalışıyor. Kapatmak istediğinize emin misiniz?"):
                self._stop_server()
                self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()

    def run(self):
        """GUI'yi başlatır"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self._log_message("Server GUI hazır", "INFO")
        self._log_message(f"Host: {self.host}, Port: {self.port}", "INFO")
        self.root.mainloop()

