import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server.network.Server import Server
from server.processing.ProcessingManager import ProcessingManager
from algorithms.KeyDistributionManager import KeyDistributionManager
from shared.utils import Logger
import base64


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
        self.decrypted_file_data = None  # Deşifrelenmiş dosya verisi
        self.decrypted_filename = None  # Deşifrelenmiş dosya adı

        self._create_widgets()
        self._setup_logging()

    def _create_widgets(self):
        """GUI bileşenlerini oluşturur"""
        main_canvas = tk.Canvas(self.root)
        main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=main_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        main_canvas.configure(yscrollcommand=scrollbar.set)
        main_canvas.bind('<Configure>', lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all")))

        main_frame = ttk.Frame(main_canvas, padding="10")
        main_canvas.create_window((0, 0), window=main_frame, anchor="nw")
        
        # Grid weight ayarları
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Başlık
        title_label = ttk.Label(main_frame, text="Kriptoloji Server - Kontrol Paneli", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 10))

        # 1. ÜST PANEL: Server Durumu
        status_frame = ttk.LabelFrame(main_frame, text="📡 Server Durumu", padding="10")
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        status_frame.columnconfigure(3, weight=1)

        # Sol taraf: Durum
        ttk.Label(status_frame, text="Durum:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.status_label = ttk.Label(status_frame, text="Durduruldu", foreground="red", font=("Arial", 10, "bold"))
        self.status_label.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Host:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.host_label = ttk.Label(status_frame, text=f"{self.host}:{self.port}")
        self.host_label.grid(row=1, column=1, sticky=tk.W)

        # Sağ taraf: İstatistik
        ttk.Label(status_frame, text="Bağlı Client:").grid(row=0, column=2, sticky=tk.W, padx=(20, 10))
        self.client_count_label = ttk.Label(status_frame, text="0", font=("Arial", 10, "bold"))
        self.client_count_label.grid(row=0, column=3, sticky=tk.W)

        ttk.Label(status_frame, text="Toplam İşlem:").grid(row=1, column=2, sticky=tk.W, padx=(20, 10))
        self.request_count_label = ttk.Label(status_frame, text="0", font=("Arial", 10, "bold"))
        self.request_count_label.grid(row=1, column=3, sticky=tk.W)

        # 2. ORTA PANEL: Detaylı İşlem Görüntüleme (Monitoring)
        process_frame = ttk.LabelFrame(main_frame, text="🔍 Anlık İşlem İzleyici (Client Talepleri)", padding="10")
        process_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        process_frame.columnconfigure(1, weight=1)

        # Şifreleme Tekniği
        ttk.Label(process_frame, text="Kullanılan Teknik:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.proc_algo_var = tk.StringVar(value="-")
        ttk.Label(process_frame, textvariable=self.proc_algo_var, foreground="blue", font=("Arial", 11)).grid(row=0, column=1, sticky=tk.W)

        # İşlem Türü
        ttk.Label(process_frame, text="İşlem Türü:", font=("Arial", 10, "bold")).grid(row=0, column=2, sticky=tk.W, padx=(20, 10))
        self.proc_type_var = tk.StringVar(value="-")
        self.proc_type_label = ttk.Label(process_frame, textvariable=self.proc_type_var, font=("Arial", 11))
        self.proc_type_label.grid(row=0, column=3, sticky=tk.W)

        # Anahtar
        ttk.Label(process_frame, text="Kullanılan Anahtar:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.proc_key_var = tk.StringVar(value="-")
        ttk.Entry(process_frame, textvariable=self.proc_key_var, state="readonly", width=40).grid(row=1, column=1, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))

        # Dosya Bilgileri (Dosya işlemleri için)
        self.file_info_frame = ttk.LabelFrame(process_frame, text="📁 Dosya Bilgileri", padding="5")
        self.file_info_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        self.file_info_frame.grid_remove()  # Başlangıçta gizle
        self.file_info_frame.columnconfigure(1, weight=1)
        self.file_info_frame.columnconfigure(3, weight=1)
        
        ttk.Label(self.file_info_frame, text="Dosya Adı:", font=("Arial", 9, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.proc_filename_var = tk.StringVar(value="-")
        ttk.Label(self.file_info_frame, textvariable=self.proc_filename_var, foreground="blue").grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(self.file_info_frame, text="Dosya Türü:", font=("Arial", 9, "bold")).grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.proc_filetype_var = tk.StringVar(value="-")
        ttk.Label(self.file_info_frame, textvariable=self.proc_filetype_var).grid(row=0, column=3, sticky=tk.W)
        
        ttk.Label(self.file_info_frame, text="Orijinal Boyut:", font=("Arial", 9, "bold")).grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.proc_original_size_var = tk.StringVar(value="-")
        ttk.Label(self.file_info_frame, textvariable=self.proc_original_size_var).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        
        ttk.Label(self.file_info_frame, text="Şifreli Boyut:", font=("Arial", 9, "bold")).grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.proc_encrypted_size_var = tk.StringVar(value="-")
        ttk.Label(self.file_info_frame, textvariable=self.proc_encrypted_size_var, foreground="green").grid(row=1, column=3, sticky=tk.W, pady=(5, 0))

        # Gelen Veri (Input)
        self.input_label_var = tk.StringVar(value="Gelen Veri (Client'tan):")
        ttk.Label(process_frame, textvariable=self.input_label_var, font=("Arial", 9, "bold")).grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        self.proc_input_text = scrolledtext.ScrolledText(process_frame, height=3, width=50, state="disabled", font=("Consolas", 10))
        self.proc_input_text.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 5))

        # Çıkan Veri (Output)
        self.output_label_var = tk.StringVar(value="İşlenmiş Sonuç (Server'dan):")
        ttk.Label(process_frame, textvariable=self.output_label_var, font=("Arial", 10, "bold"), foreground="dark green").grid(row=5, column=0, sticky=tk.W, padx=(0, 10))
        
        ttk.Button(process_frame, text="📋 Sonucu Kopyala", command=self._copy_result).grid(row=5, column=3, sticky=tk.E)

        self.proc_output_text = scrolledtext.ScrolledText(process_frame, height=4, width=50, state="disabled", font=("Consolas", 11, "bold"), background="#f0fff0")
        self.proc_output_text.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E))

        # 3. ALT PANEL: Manuel İşlem Araçları
        manual_frame = ttk.LabelFrame(main_frame, text="🛠️ Manuel İşlem Araçları", padding="10")
        manual_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        manual_frame.columnconfigure(1, weight=1)

        # Notebook ile Metin ve Dosya sekmeleri
        manual_notebook = ttk.Notebook(manual_frame)
        manual_notebook.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))

        # METİN İŞLEME SEKME
        text_tab = ttk.Frame(manual_notebook)
        manual_notebook.add(text_tab, text="📝 Metin İşleme")
        text_tab.columnconfigure(1, weight=1)

        # Algoritma & Key (Metin için)
        ttk.Label(text_tab, text="Algoritma:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.man_algo_var = tk.StringVar(value="caesar")
        algos = ["caesar", "vigenere", "affine", "hill", "playfair", "railfence", "columnar", "polybius", "substitution", "route", "pigpen", "aes", "des", "aes_manual", "des_manual", "rsa", "rsa_manual"]
        self.man_algo_combo = ttk.Combobox(text_tab, textvariable=self.man_algo_var, values=algos, state="readonly")
        self.man_algo_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)

        ttk.Label(text_tab, text="Anahtar:").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.man_key_var = tk.StringVar()
        ttk.Entry(text_tab, textvariable=self.man_key_var, width=20).grid(row=0, column=3, sticky=(tk.W, tk.E))

        # Manuel Giriş (Metin)
        ttk.Label(text_tab, text="Giriş Verisi:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        self.man_input_text = scrolledtext.ScrolledText(text_tab, height=4, width=30)
        self.man_input_text.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # Manuel Çıkış (Metin)
        ttk.Label(text_tab, text="Sonuç:").grid(row=1, column=2, sticky=tk.W, pady=(10, 0), padx=(10, 0))
        self.man_output_text = scrolledtext.ScrolledText(text_tab, height=4, width=30)
        self.man_output_text.grid(row=2, column=2, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10), padx=(10, 0))

        # Manuel Butonlar (Metin)
        man_btn_frame = ttk.Frame(text_tab)
        man_btn_frame.grid(row=3, column=0, columnspan=4, sticky=tk.E)
        
        ttk.Button(man_btn_frame, text="➡️ Şifrele", command=lambda: self._manual_process("ENCRYPT")).pack(side=tk.LEFT, padx=5)
        ttk.Button(man_btn_frame, text="⬅️ Deşifrele", command=lambda: self._manual_process("DECRYPT")).pack(side=tk.LEFT, padx=5)
        ttk.Button(man_btn_frame, text="🧹 Temizle", command=self._clear_manual).pack(side=tk.LEFT, padx=5)

        # DOSYA İŞLEME SEKME
        file_tab = ttk.Frame(manual_notebook)
        manual_notebook.add(file_tab, text="📁 Dosya İşleme")
        file_tab.columnconfigure(1, weight=1)

        # Dosya Seçimi
        file_select_frame = ttk.Frame(file_tab)
        file_select_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        file_select_frame.columnconfigure(1, weight=1)

        ttk.Label(file_select_frame, text="Şifrelenmiş Dosya:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.server_file_path_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.server_file_path_var, state="readonly").grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(file_select_frame, text="📂 Dosya Seç", command=self._select_server_file).grid(row=0, column=2)

        # Dosya Bilgileri
        self.server_file_info_text = tk.Text(file_tab, height=3, state=tk.DISABLED, font=("Consolas", 9))
        self.server_file_info_text.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))

        # Algoritma & Key (Dosya için)
        ttk.Label(file_tab, text="Algoritma:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
        self.server_file_algo_var = tk.StringVar(value="aes")
        self.server_file_algo_combo = ttk.Combobox(file_tab, textvariable=self.server_file_algo_var, values=algos, state="readonly")
        self.server_file_algo_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5)

        ttk.Label(file_tab, text="Anahtar:").grid(row=2, column=2, sticky=tk.W, padx=(10, 5))
        self.server_file_key_var = tk.StringVar()
        ttk.Entry(file_tab, textvariable=self.server_file_key_var, width=20).grid(row=2, column=3, sticky=(tk.W, tk.E))

        # Dosya İşlem Butonları
        file_btn_frame = ttk.Frame(file_tab)
        file_btn_frame.grid(row=3, column=0, columnspan=4, sticky=tk.E, pady=(10, 0))
        
        ttk.Button(file_btn_frame, text="🔓 Dosyayı Deşifrele", command=self._decrypt_server_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_btn_frame, text="💾 Sonucu Kaydet", command=self._save_decrypted_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_btn_frame, text="🧹 Temizle", command=self._clear_server_file).pack(side=tk.LEFT, padx=5)

        # Sonuç Bilgisi
        self.server_file_result_text = tk.Text(file_tab, height=4, state=tk.DISABLED, font=("Consolas", 9))
        self.server_file_result_text.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))

        # 4. KONTROL & LOG
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))
        bottom_frame.columnconfigure(0, weight=1)

        control_frame = ttk.Frame(bottom_frame)
        control_frame.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))

        self.start_button = ttk.Button(control_frame, text="Server'ı Başlat", 
                                      command=self._start_server)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_button = ttk.Button(control_frame, text="Server'ı Durdur", 
                                     command=self._stop_server, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(control_frame, text="Logları Temizle", command=self._clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Çıkış", command=self._on_closing).pack(side=tk.RIGHT)

        log_frame = ttk.LabelFrame(bottom_frame, text="📜 Sistem Logları", padding="5")
        log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, state=tk.DISABLED,
                                                 wrap=tk.WORD, font=("Consolas", 8))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _manual_process(self, op_type):
        """Manuel işlemi gerçekleştirir."""
        algo = self.man_algo_var.get()
        key = self.man_key_var.get()
        input_data = self.man_input_text.get("1.0", tk.END).strip()
        
        if not input_data:
            messagebox.showwarning("Uyarı", "Giriş verisi boş olamaz!")
            return
            
        if self.server and self.server.processing_callback:
            try:
                # String veriyi bytes'a çevir
                data_bytes = input_data.encode('utf-8')
                
                # İşlemi yap
                result = self.server.processing_callback(data_bytes, op_type, algo, key, {})
                
                if result and result.get('success'):
                    res_data = result['data']
                    try:
                        res_str = res_data.decode('utf-8')
                    except:
                        res_str = res_data.hex()
                        
                    self.man_output_text.delete("1.0", tk.END)
                    self.man_output_text.insert(tk.END, res_str)
                    self._log_message(f"🛠️ Manuel işlem başarılı: {algo} ({op_type})", "SUCCESS")
                else:
                    err = result.get('error', 'Bilinmeyen hata')
                    messagebox.showerror("Hata", f"İşlem başarısız: {err}")
            except Exception as e:
                messagebox.showerror("Hata", f"Sistemsel hata: {str(e)}")
        else:
            messagebox.showerror("Hata", "ProcessingManager hazır değil!")

    def _clear_manual(self):
        """Manuel sekmesini temizler."""
        self.man_input_text.delete("1.0", tk.END)
        self.man_output_text.delete("1.0", tk.END)
        self.man_key_var.set("")

    def _select_server_file(self):
        """Server tarafında şifrelenmiş dosya seçer."""
        file_path = filedialog.askopenfilename(
            title="Şifrelenmiş Dosya Seçin",
            filetypes=[
                ("Şifrelenmiş Dosyalar", "*.enc"),
                ("Tüm Dosyalar", "*.*")
            ]
        )
        
        if file_path:
            self.server_file_path_var.set(file_path)
            self._update_server_file_info(file_path)

    def _update_server_file_info(self, file_path):
        """Seçilen dosya bilgilerini gösterir."""
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            info_text = f"Dosya: {filename}\n"
            info_text += f"Boyut: {file_size:,} bytes\n"
            info_text += f"Yol: {file_path}"
            
            self.server_file_info_text.config(state=tk.NORMAL)
            self.server_file_info_text.delete("1.0", tk.END)
            self.server_file_info_text.insert("1.0", info_text)
            self.server_file_info_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya bilgisi alınamadı: {str(e)}")

    def _decrypt_server_file(self):
        """Server tarafında dosyayı deşifreler."""
        file_path = self.server_file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Uyarı", "Lütfen geçerli bir dosya seçin.")
            return

        algorithm = self.server_file_algo_var.get()
        key = self.server_file_key_var.get().strip()
        
        if not key:
            messagebox.showwarning("Uyarı", "Lütfen anahtar girin.")
            return

        if not self.server or not self.server.processing_callback:
            messagebox.showerror("Hata", "ProcessingManager hazır değil!")
            return

        def decrypt_thread():
            try:
                # Dosyayı oku
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()

                # Metadata hazırla
                metadata = {
                    'filename': os.path.basename(file_path),
                    'extension': os.path.splitext(file_path)[1].lower(),
                    'file_size': len(encrypted_data)
                }

                # Deşifreleme işlemi
                result = self.server.processing_callback(
                    encrypted_data, 
                    'DECRYPT', 
                    algorithm, 
                    key, 
                    metadata
                )

                if result and result.get('success'):
                    self.decrypted_file_data = result['data']
                    original_filename = os.path.basename(file_path)
                    if original_filename.endswith('.enc'):
                        self.decrypted_filename = original_filename[:-4]  # .enc'i kaldır
                    else:
                        self.decrypted_filename = original_filename
                    
                    result_info = f"✅ Deşifreleme başarılı!\n\n"
                    result_info += f"📁 Şifreli Dosya: {original_filename}\n"
                    result_info += f"📁 Çözülmüş Dosya: {self.decrypted_filename}\n"
                    result_info += f"🔐 Algoritma: {algorithm}\n"
                    result_info += f"🔑 Anahtar: {key}\n"
                    result_info += f"📊 Şifreli Boyut: {len(encrypted_data):,} bytes\n"
                    result_info += f"📊 Orijinal Boyut: {len(self.decrypted_file_data):,} bytes\n\n"
                    result_info += f"💾 Dosyayı kaydetmek için 'Sonucu Kaydet' butonuna tıklayın."
                    
                    self.root.after(0, lambda: self._update_server_file_result(result_info))
                    self.root.after(0, lambda: self._log_message(f"✅ Dosya deşifrelendi: {original_filename} → {self.decrypted_filename}", "SUCCESS"))
                else:
                    error_msg = result.get('error', 'Bilinmeyen hata') if result else 'İşlem başarısız'
                    self.root.after(0, lambda: messagebox.showerror("Hata", f"Deşifreleme başarısız: {error_msg}"))
                    self.root.after(0, lambda: self._log_message(f"❌ Dosya deşifreleme hatası: {error_msg}", "ERROR"))

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Hata", f"Dosya deşifreleme hatası: {str(e)}"))
                self.root.after(0, lambda: self._log_message(f"❌ Dosya deşifreleme hatası: {str(e)}", "ERROR"))

        threading.Thread(target=decrypt_thread, daemon=True).start()

    def _update_server_file_result(self, result_info):
        """Server dosya sonuç bilgisini günceller."""
        self.server_file_result_text.config(state=tk.NORMAL)
        self.server_file_result_text.delete("1.0", tk.END)
        self.server_file_result_text.insert("1.0", result_info)
        self.server_file_result_text.config(state=tk.DISABLED)

    def _save_decrypted_file(self):
        """Deşifrelenmiş dosyayı kaydeder."""
        if not self.decrypted_file_data:
            messagebox.showwarning("Uyarı", "Kaydedilecek deşifrelenmiş dosya yok.")
            return

        filename = filedialog.asksaveasfilename(
            title="Deşifrelenmiş Dosyayı Kaydet",
            initialfile=self.decrypted_filename,
            filetypes=[("Tüm Dosyalar", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.decrypted_file_data)
                messagebox.showinfo("Başarılı", f"Dosya kaydedildi:\n{filename}")
                self._log_message(f"💾 Deşifrelenmiş dosya kaydedildi: {filename}", "SUCCESS")
            except Exception as e:
                messagebox.showerror("Hata", f"Kaydetme hatası: {str(e)}")
                self._log_message(f"❌ Dosya kaydetme hatası: {str(e)}", "ERROR")

    def _clear_server_file(self):
        """Server dosya sekmesini temizler."""
        self.server_file_path_var.set("")
        self.server_file_key_var.set("")
        self.decrypted_file_data = None
        self.decrypted_filename = None
        self.server_file_info_text.config(state=tk.NORMAL)
        self.server_file_info_text.delete("1.0", tk.END)
        self.server_file_info_text.config(state=tk.DISABLED)
        self.server_file_result_text.config(state=tk.NORMAL)
        self.server_file_result_text.delete("1.0", tk.END)
        self.server_file_result_text.config(state=tk.DISABLED)

    def _setup_logging(self):
        """Logger'a GUI handler ekler"""
        pass

    def _log_message(self, message, level="INFO"):
        """Log mesajını GUI'ye ekler"""
        if not hasattr(self, 'log_text'):
            return
            
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
                try:
                    self.root.after(0, lambda: messagebox.showerror("Hata", f"Server başlatılamadı:\n{str(e)}"))
                except:
                    pass
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
                
                # Detaylı bilgiler
                key = event_data.get('key', '')
                input_data = event_data.get('input_data', '')
                output_data = event_data.get('output_data', '')
                
                is_binary_in = event_data.get('is_binary', False)
                
                if event_type == 'operation_start':
                    # Log
                    self._log_message(f"📥 İşlem başladı: {client} → {operation.upper()} ({algorithm})", "INFO")
                    self.request_count += 1
                    self._update_stats()
                    
                    # Detay Panelini Güncelle (Başlangıç)
                    self.proc_algo_var.set(algorithm)
                    self.proc_type_var.set(operation.upper())
                    self.proc_key_var.set(str(key))
                    
                    # Dosya bilgilerini al ve göster
                    filename = event_data.get('filename', '')
                    file_extension = event_data.get('extension', '')
                    file_size = event_data.get('file_size', 0)
                    
                    if filename:
                        # Dosya işlemi
                        self.file_info_frame.grid()  # Göster
                        self.proc_filename_var.set(filename)
                        self.proc_filetype_var.set(file_extension if file_extension else "Bilinmiyor")
                        self.proc_original_size_var.set(f"{file_size:,} bytes" if file_size > 0 else "-")
                        self.proc_encrypted_size_var.set("-")  # Henüz şifrelenmedi
                    else:
                        # Metin işlemi
                        self.file_info_frame.grid_remove()  # Gizle
                        self.proc_filename_var.set("-")
                        self.proc_filetype_var.set("-")
                        self.proc_original_size_var.set("-")
                        self.proc_encrypted_size_var.set("-")
                    
                    # Renklendirme
                    if operation.upper() == "ENCRYPT":
                        self.proc_type_label.config(foreground="red")
                        self.input_label_var.set("🔹 Gelen Veri (MASKELENDİ):")
                        self.output_label_var.set("🔐 ŞİFRELENMİŞ SONUÇ (Kopyalayınız):")
                        input_display = "******** (Düz metin güvenlik için gizlendi)"
                    else:
                        self.proc_type_label.config(foreground="green")
                        self.input_label_var.set("🔐 Şifreli Giriş:")
                        self.output_label_var.set("🔓 DEŞİFRE EDİLMİŞ METİN:")
                        prefix = "[HEX] " if is_binary_in else ""
                        input_display = prefix + str(input_data)
                    
                    # Input kutusu
                    self.proc_input_text.config(state="normal")
                    self.proc_input_text.delete("1.0", tk.END)
                    
                    # Veri çok büyükse buda (Performans için)
                    if len(input_display) > 5000:
                        input_display = input_display[:4997] + "..."
                        
                    self.proc_input_text.insert(tk.END, input_display)
                    self.proc_input_text.config(state="disabled")
                    
                    # Output kutusunu temizle/bekliyor yaz
                    self.proc_output_text.config(state="normal")
                    self.proc_output_text.delete("1.0", tk.END)
                    self.proc_output_text.insert(tk.END, "İşleniyor...")
                    self.proc_output_text.config(state="disabled")

                elif event_type == 'operation_success':
                    data_size = event_data.get('data_size', 0)
                    result_size = event_data.get('result_size', 0)
                    res_is_binary = event_data.get('res_is_binary', False)
                    filename = event_data.get('filename', '')

                    self._log_message(f"✅ İşlem tamamlandı: {client} → {operation.upper()} ({algorithm}) - Veri: {data_size}B → {result_size}B", "SUCCESS")
                    
                    # Dosya işlemi ise şifreli boyutu güncelle
                    if filename:
                        self.proc_encrypted_size_var.set(f"{result_size:,} bytes" if result_size > 0 else "-")
                        # Şifreli dosya adını göster
                        encrypted_filename = filename + ".enc" if operation.upper() == "ENCRYPT" else filename.replace(".enc", "")
                        self.proc_filename_var.set(encrypted_filename)
                    
                    # Output kutusunu güncelle
                    self.proc_output_text.config(state="normal")
                    self.proc_output_text.delete("1.0", tk.END)
                    
                    # Dosya işlemi için özel format
                    if filename and operation.upper() == "ENCRYPT":
                        full_output = f"✅ ŞİFRELENMİŞ DOSYA BİLGİLERİ:\n"
                        full_output += f"📁 Dosya Adı: {filename}.enc\n"
                        full_output += f"🔐 Algoritma: {algorithm}\n"
                        full_output += f"🔑 Anahtar: {key}\n"
                        full_output += f"📊 Orijinal Boyut: {data_size:,} bytes\n"
                        full_output += f"📊 Şifreli Boyut: {result_size:,} bytes\n"
                        full_output += f"📝 İşlem Türü: {operation.upper()}\n\n"
                        full_output += f"⚠️ NOT: Şifreli dosya client'a gönderildi. Deşifreleme için bu bilgileri kullanın!"
                    elif filename and operation.upper() == "DECRYPT":
                        full_output = f"✅ DEŞİFRE EDİLMİŞ DOSYA BİLGİLERİ:\n"
                        full_output += f"📁 Dosya Adı: {filename.replace('.enc', '')}\n"
                        full_output += f"🔐 Algoritma: {algorithm}\n"
                        full_output += f"🔑 Anahtar: {key}\n"
                        full_output += f"📊 Şifreli Boyut: {data_size:,} bytes\n"
                        full_output += f"📊 Orijinal Boyut: {result_size:,} bytes\n"
                        full_output += f"📝 İşlem Türü: {operation.upper()}\n\n"
                        full_output += f"✅ Dosya başarıyla deşifrelendi ve client'a gönderildi!"
                    else:
                        # Metin işlemi için normal format
                        prefix = "[HEX] " if res_is_binary else ""
                        full_output = prefix + str(output_data)
                    
                    # Veri çok büyükse buda (Performans için)
                    if len(full_output) > 5000:
                        full_output = full_output[:4997] + "..."
                        
                    self.proc_output_text.insert(tk.END, full_output)
                    self.proc_output_text.config(state="disabled")

                elif event_type == 'operation_error':
                    error = event_data.get('error', 'Bilinmeyen hata')
                    self._log_message(f"❌ İşlem hatası ({client}): {error}", "ERROR")
                    
                    self.proc_output_text.config(state="normal")
                    self.proc_output_text.delete("1.0", tk.END)
                    self.proc_output_text.insert(tk.END, f"HATA: {error}")
                    self.proc_output_text.config(state="disabled")

            except Exception as e:
                self._log_message(f"GUI güncelleme hatası: {str(e)}", "ERROR")
        
        self.root.after(0, update_gui)

    def _copy_result(self):
        """İşlenmiş sonucu panoya kopyalar"""
        data = self.proc_output_text.get("1.0", tk.END).strip()
        if data and data != "İşleniyor...":
            # [HEX] prefix'ini temizle eğer varsa
            if data.startswith("[HEX] "):
                data = data[6:]
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            messagebox.showinfo("Başarılı", "Sonuç panoya kopyalandı!")

    def _copy_intercept_key(self):
        """Anahtar kopyalar"""
        data = self.proc_key_var.get().strip()
        if data and data != "-":
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            messagebox.showinfo("Başarılı", "Anahtar kopyalandı!")

    def _clear_logs(self):
        """Log alanını temizler"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _on_closing(self):
        """Pencere kapatıldığında çağrılır"""
        if self.running:
            if messagebox.askokcancel("Çıkış", "Server hala çalışıyor. Kapatmak istediğinize emin misiniz?"):
                self._stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        """GUI'yi başlatır"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self._log_message("Server GUI hazır", "INFO")
        self._log_message(f"Host: {self.host}, Port: {self.port}", "INFO")
        self.root.mainloop()
