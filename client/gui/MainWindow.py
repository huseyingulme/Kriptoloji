import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
import time
from typing import Optional, Dict, Any, Tuple
from client.network.Client import Client
from client.file.FileManager import FileManager
from client.hybrid_encryption import HybridEncryptionManager
from shared.utils import Logger
from shared.utils import FileUtils, Logger

class MainWindow:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Kriptoloji Projesi - Şifreleme/Çözme Sistemi")
        self.root.geometry("900x1000")
        self.root.resizable(True, True)

        self.client: Optional[Client] = None
        self.file_manager = FileManager()
        self.hybrid_manager = HybridEncryptionManager()

        self.server_host_var = tk.StringVar(value="localhost")
        self.server_port_var = tk.StringVar(value="12345")

        self.input_data = tk.StringVar()
        self.algorithm_var = tk.StringVar(value="caesar")
        self.key_var = tk.StringVar()
        self.operation_var = tk.StringVar(value="encrypt")
        self.server_status_var = tk.StringVar(value="Bağlantı yok")
        self.implementation_mode_var = tk.StringVar(value="library")  # library veya manual

        self._create_widgets()
        self._create_menu()

        self._on_algorithm_changed()
        self._on_operation_changed()

    def _get_algorithm_list(self):
        """Tüm şifreleme algoritmalarının listesini döndürür."""
        return [
            # Klasik Şifreleme
            "caesar", "vigenere", "affine", "hill", "playfair", "railfence", "columnar", "polybius",
            "substitution", "route", "pigpen",
            # Modern Simetrik Şifreleme (Kütüphaneli)
            "aes", "des", "idea", "iron",
            # Modern Simetrik Şifreleme (Manuel)
            "aes_manual", "des_manual",
            # Asimetrik & Hibrit Şifreleme
            "rsa", "rsa_manual",
            "hybrid_aes", "hybrid_aes_manual", "hybrid_des", "hybrid_des_manual",
            "hybrid_ecc_aes", "hybrid_ecc_aes_manual", "hybrid_ecc_des", "hybrid_ecc_des_manual"
        ]

    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        title_label = ttk.Label(main_frame, text="Kriptoloji Projesi",
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        connection_frame = ttk.LabelFrame(main_frame, text="Server Bağlantı Ayarları", padding="10")
        connection_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        connection_frame.columnconfigure(1, weight=1)
        connection_frame.columnconfigure(3, weight=1)

        ttk.Label(connection_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        ttk.Entry(connection_frame, textvariable=self.server_host_var, width=15).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))

        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        ttk.Entry(connection_frame, textvariable=self.server_port_var, width=10).grid(row=0, column=3, sticky=tk.W, padx=(0, 10))

        ttk.Button(connection_frame, text="Bağlan", command=self._connect_to_server).grid(row=0, column=4, padx=(10, 0))
        ttk.Button(connection_frame, text="Bağlantıyı Kes", command=self._disconnect_from_server).grid(row=0, column=5, padx=(5, 0))

        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(status_frame, text="Server Durumu:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, textvariable=self.server_status_var)
        self.status_label.pack(side=tk.LEFT, padx=(5, 0))

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self._create_text_tab()

        self._create_file_tab()

        self._create_saved_files_tab()

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))

        ttk.Button(button_frame, text="Temizle", command=self._clear_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Yeniden Bağlan", command=self._reconnect_server).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Test Bağlantısı", command=self._test_connection).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Çıkış", command=self._on_closing).pack(side=tk.RIGHT)

    def _create_text_tab(self):
        text_frame = ttk.Frame(self.notebook)
        self.notebook.add(text_frame, text="Metin İşleme")

        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        ttk.Label(text_frame, text="Metin:").grid(row=0, column=0, sticky=tk.W, pady=(10, 5))
        self.text_input = scrolledtext.ScrolledText(text_frame, height=8, width=50)
        self.text_input.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        settings_frame = ttk.LabelFrame(text_frame, text="Ayarlar", padding="10")
        settings_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(settings_frame, text="Algoritma:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        algorithm_combo = ttk.Combobox(settings_frame, textvariable=self.algorithm_var,
                                     values=self._get_algorithm_list(), state="readonly", width=20)
        algorithm_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        algorithm_combo.bind("<<ComboboxSelected>>", self._on_algorithm_changed)

        ttk.Button(settings_frame, text="Algoritma Bilgisi", command=self._show_algorithm_info).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(settings_frame, text="Örnek Anahtar", command=self._fill_example_key).grid(row=0, column=3, padx=(5, 0))

        ttk.Label(settings_frame, text="Anahtar:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.key_entry = ttk.Entry(settings_frame, textvariable=self.key_var, width=20)
        self.key_entry.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        self.key_entry.bind('<FocusIn>', self._on_key_focus_in)
        self.key_entry.bind('<FocusOut>', self._on_key_focus_out)
        self.key_entry.bind('<KeyRelease>', self._on_key_validate)

        self.key_info_label = ttk.Label(settings_frame, text="", foreground="blue")
        self.key_info_label.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=(10, 0), pady=(10, 0))

        self.key_status_label = ttk.Label(settings_frame, text="", foreground="red")
        self.key_status_label.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))

        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))

        tk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var,
                       value="encrypt", command=self._on_operation_changed).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var,
                       value="decrypt", command=self._on_operation_changed).pack(side=tk.LEFT)

        self.process_button = ttk.Button(settings_frame, text="İşlemi Başlat", command=self._process_text)
        self.process_button.grid(row=4, column=0, pady=(10, 0))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(settings_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(10, 0), pady=(10, 0))

        ttk.Label(text_frame, text="Sonuç:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.text_output = scrolledtext.ScrolledText(text_frame, height=8, width=50, state=tk.DISABLED)
        self.text_output.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        result_button_frame = ttk.Frame(text_frame)
        result_button_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))

        ttk.Button(result_button_frame, text="Sonucu Kaydet", command=self._save_text_result).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(result_button_frame, text="Sonucu Kopyala", command=self._copy_text_result).pack(side=tk.LEFT, padx=(0, 5))

    def _create_file_tab(self):
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="Dosya İşleme")

        file_frame.columnconfigure(1, weight=1)
        file_frame.rowconfigure(2, weight=1)

        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 10))
        file_select_frame.columnconfigure(1, weight=1)

        ttk.Label(file_select_frame, text="Dosya:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path_var, state="readonly").grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(file_select_frame, text="Dosya Seç", command=self._select_file).grid(row=0, column=2)

        self.file_info_text = tk.Text(file_frame, height=4, state=tk.DISABLED)
        self.file_info_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        settings_frame = ttk.LabelFrame(file_frame, text="Ayarlar", padding="10")
        settings_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(settings_frame, text="Algoritma:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        algorithm_combo = ttk.Combobox(settings_frame, textvariable=self.algorithm_var,
                                     values=self._get_algorithm_list(), state="readonly", width=20)
        algorithm_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        algorithm_combo.bind("<<ComboboxSelected>>", self._on_algorithm_changed)

        ttk.Button(settings_frame, text="Algoritma Bilgisi", command=self._show_algorithm_info).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(settings_frame, text="Örnek Anahtar", command=self._fill_example_key).grid(row=0, column=3, padx=(5, 0))
        ttk.Button(settings_frame, text="❓ Deşifreleme Yardımı", command=self._show_decryption_help).grid(row=0, column=4, padx=(5, 0))

        ttk.Label(settings_frame, text="Anahtar:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.file_key_entry = ttk.Entry(settings_frame, textvariable=self.key_var, width=20)
        self.file_key_entry.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        self.file_key_entry.bind('<FocusIn>', self._on_key_focus_in)
        self.file_key_entry.bind('<FocusOut>', self._on_key_focus_out)
        self.file_key_entry.bind('<KeyRelease>', self._on_key_validate)

        self.file_key_info_label = ttk.Label(settings_frame, text="", foreground="blue")
        self.file_key_info_label.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=(10, 0), pady=(10, 0))

        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))

        tk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var,
                       value="encrypt", command=self._on_operation_changed).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var,
                       value="decrypt", command=self._on_operation_changed).pack(side=tk.LEFT)

        self.file_process_button = ttk.Button(settings_frame, text="Dosyayı İşle", command=self._process_file)
        self.file_process_button.grid(row=3, column=0, pady=(10, 0))

        self.file_progress_var = tk.DoubleVar()
        self.file_progress_bar = ttk.Progressbar(settings_frame, variable=self.file_progress_var, maximum=100)
        self.file_progress_bar.grid(row=3, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(10, 0), pady=(10, 0))

        ttk.Label(file_frame, text="İşlem Sonucu:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.file_result_text = tk.Text(file_frame, height=6, state=tk.DISABLED)
        self.file_result_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        result_button_frame = ttk.Frame(file_frame)
        result_button_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))

        ttk.Button(result_button_frame, text="Sonucu Kaydet", command=self._save_file_result).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(result_button_frame, text="Sonucu Aç", command=self._open_file_result).pack(side=tk.LEFT)

    def _create_saved_files_tab(self):
        saved_frame = ttk.Frame(self.notebook)
        self.notebook.add(saved_frame, text="Kayıtlı Dosyalar")

        saved_frame.columnconfigure(0, weight=1)
        saved_frame.rowconfigure(1, weight=1)

        header_frame = ttk.Frame(saved_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(10, 10))
        header_frame.columnconfigure(0, weight=1)

        ttk.Label(header_frame, text="Kayıtlı Dosyalar", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky=tk.W)
        ttk.Button(header_frame, text="Yenile", command=self._refresh_saved_files).grid(row=0, column=1)

        self.saved_files_tree = ttk.Treeview(saved_frame, columns=("size", "type", "algorithm"), show="tree headings")
        self.saved_files_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.saved_files_tree.heading("#0", text="Dosya Adı")
        self.saved_files_tree.heading("size", text="Boyut")
        self.saved_files_tree.heading("type", text="Tip")
        self.saved_files_tree.heading("algorithm", text="Algoritma")

        scrollbar = ttk.Scrollbar(saved_frame, orient=tk.VERTICAL, command=self.saved_files_tree.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.saved_files_tree.configure(yscrollcommand=scrollbar.set)

        file_ops_frame = ttk.Frame(saved_frame)
        file_ops_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Button(file_ops_frame, text="Yükle", command=self._load_saved_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_ops_frame, text="Sil", command=self._delete_saved_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_ops_frame, text="Bilgi", command=self._show_file_info).pack(side=tk.LEFT)

        self._refresh_saved_files()

    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Dosya", menu=file_menu)
        file_menu.add_command(label="Yeni", command=self._clear_all)
        file_menu.add_separator()
        file_menu.add_command(label="Çıkış", command=self._on_closing)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Yardım", menu=help_menu)
        help_menu.add_command(label="Hakkında", command=self._show_about)

    def _connect_to_server(self):
        def connect_thread():
            try:
                host = self.server_host_var.get().strip()
                port = int(self.server_port_var.get().strip())

                if not host:
                    self.root.after(0, lambda: messagebox.showerror("Hata", "Server IP adresi giriniz."))
                    return

                if port <= 0 or port > 65535:
                    self.root.after(0, lambda: messagebox.showerror("Hata", "Geçerli bir port numarası giriniz (1-65535)."))
                    return

                self.client = Client(host, port)
                if self.client.connect():
                    # Handshake yap - RSA public key al
                    try:
                        public_key = self.client.request_public_key()
                        if public_key:
                            Logger.info("RSA public key alındı", "MainWindow")
                            self.hybrid_manager.set_server_public_key(public_key)
                        
                        ecc_public_key = self.client.request_ecc_public_key()
                        if ecc_public_key:
                            Logger.info("ECC public key alındı", "MainWindow")
                            self.hybrid_manager.server_ecc_public_key = ecc_public_key
                    except Exception as e:
                        Logger.warning(f"Public key'ler alınamadı: {str(e)}", "MainWindow")
                    
                    self.root.after(0, lambda: self.server_status_var.set(f"Bağlı ({host}:{port})"))
                    self.root.after(0, lambda: self.status_label.config(foreground="green"))
                    self.root.after(0, lambda: messagebox.showinfo("Başarılı", f"Server'a bağlandı: {host}:{port}"))
                else:
                    self.root.after(0, lambda: self.server_status_var.set("Bağlantı hatası"))
                    self.root.after(0, lambda: self.status_label.config(foreground="red"))
                    error_msg = (
                        f"Server'a bağlanılamadı: {host}:{port}\n\n"
                        "Çözüm önerileri:\n"
                        "1. Server'ın çalıştığından emin olun\n"
                        "2. Server IP ve port bilgilerini kontrol edin\n"
                        "3. Firewall ayarlarını kontrol edin\n"
                        "4. Server'ı başlatmak için: python main.py server"
                    )
                    self.root.after(0, lambda: messagebox.showerror("Bağlantı Hatası", error_msg))
            except ValueError:
                self.root.after(0, lambda: messagebox.showerror("Hata", "Geçerli bir port numarası giriniz."))
            except Exception as e:
                error_msg = (
                    f"Bağlantı hatası: {str(e)}\n\n"
                    "Çözüm önerileri:\n"
                    "1. Server'ın çalıştığından emin olun\n"
                    "2. Server IP ve port bilgilerini kontrol edin\n"
                    "3. Firewall ayarlarını kontrol edin"
                )
                self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))

        threading.Thread(target=connect_thread, daemon=True).start()

    def _disconnect_from_server(self):
        if self.client:
            self.client.disconnect()
            self.client = None
        self.server_status_var.set("Bağlantı yok")
        self.status_label.config(foreground="black")

    def _reconnect_server(self):
        self._disconnect_from_server()
        self._connect_to_server()

    def _test_connection(self):

        if not self.client or not self.client.is_connected():
            messagebox.showwarning("Uyarı", "Önce server'a bağlanın.")
            return

        def test_thread():
            try:
                if self.client.ping_server():
                    self.root.after(0, lambda: messagebox.showinfo("Başarılı", "Server bağlantısı aktif!"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Hata", "Server bağlantısı başarısız!"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Hata", f"Bağlantı testi başarısız: {str(e)}"))

        threading.Thread(target=test_thread, daemon=True).start()

    def _process_text(self):
        input_text = self.text_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Uyarı", "Giriş verisi boş olamaz!")
            return

        operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
        algorithm = self.algorithm_var.get()
        key = self.key_var.get().strip()

        # Şifrelemede anahtar boş veya otomatik ise üret
        if operation == "ENCRYPT":
            if not key or "OTOMATİK" in key.upper():
                if algorithm == "pigpen" or algorithm == "polybius":
                    key = ""
                else:
                    key = self._generate_random_key(algorithm)
                    self.key_var.set(key)
        else:
            # Çözmede anahtar boş olamaz
            if not key and algorithm not in ["pigpen", "polybius"]:
                messagebox.showwarning("Uyarı", "Lütfen deşifreleme anahtarını girin.")
                return

        if not self._validate_key(key):
            messagebox.showerror("Hata", "Geçersiz anahtar formatı.")
            return

        def process_thread():
            try:
                # text değişkenini iç fonksiyon içinde kullanmak için nonlocal veya yeniden okuma
                process_text = self.text_input.get("1.0", tk.END).strip()
                
                self.root.after(0, lambda: self.progress_var.set(10))
                self.root.after(0, lambda: self.process_button.config(state="disabled", text="İşleniyor..."))

                operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
                algorithm = self.algorithm_var.get()
                key = self.key_var.get()

                if not key and not algorithm.startswith("hybrid_") and algorithm != "pigpen":
                    self.root.after(0, lambda: messagebox.showwarning("Uyarı", "Lütfen anahtar girin."))
                    return

                self.root.after(0, lambda: self.progress_var.set(30))
                
                # Hibrit algoritmalar için özel durum: Magic Base64/Hex parse işlemini atla
                if algorithm.startswith("hybrid_") and operation == "DECRYPT":
                    data = process_text.encode('utf-8')
                    Logger.info(f"Hibrit paket ham metin olarak alındı.", "MainWindow")
                # Çözme işlemi için hex ve base64 string kontrolü
                elif operation == "DECRYPT":
                    import base64 as b64
                    
                    # Klasik şifreleme algoritmaları listesi (boşlukları korumalı)
                    classic_algorithms = ['caesar', 'caesar_cipher', 'vigenere', 'vigenere_cipher', 
                                         'substitution', 'substitution_cipher', 'affine', 'affine_cipher',
                                         'playfair', 'playfair_cipher', 'hill', 'hill_cipher',
                                         'polybius', 'polybius_cipher', 'railfence', 'rail_fence',
                                         'route', 'route_cipher', 'pigpen', 'pigpen_cipher']
                    is_classic_algorithm = algorithm.lower() in classic_algorithms
                    
                    # --- GELİŞMİŞ ETİKET TEMİZLEME ---
                    # Eğer metin içinde bilinen etiketler varsa, etiketten sonrasını al
                    labels = [
                        "Şifrelenmiş Veri (Hex):", "Şifrelenmiş Veri (Base64):", 
                        "Hex Formatı:", "Hex Format:", "Base64 Formatı:", "Base64 Format:",
                        "Şifrelenmiş Metin:", "Çözülmüş Veri (Hex):", "RSA_PRIVATE_KEY:",
                        "ŞİFRELENMİŞ VERİ:"
                    ]
                    
                    p_text_lower = process_text.lower()
                    found_label = False
                    for label in labels:
                        if label.lower() in p_text_lower:
                            # Etiketi bul ve sonrasını al
                            idx = p_text_lower.find(label.lower())
                            after_label = process_text[idx + len(label):].strip()
                            # Eğer birden fazla etiket varsa (örn RSA veya Hex+Base64), 
                            # bir sonraki etikete kadar olan kısmı almaya çalışabiliriz 
                            # veya sadece bir sonraki boşluğa bakabiliriz.
                            # Ama şimdilik sadece satır sonuna veya bir sonraki etikete kadar alalım.
                            potential_text = after_label.split('\n')[0].strip()
                            if not potential_text and '\n' in after_label:
                                potential_text = after_label.split('\n')[1].strip()
                            
                            if potential_text:
                                process_text = potential_text
                                Logger.info(f"Etiket bulundu ({label}) ve metin ayıklandı.", "MainWindow")
                                found_label = True
                                break
                    
                    # Eğer klasik algoritma ise ve etiket bulunmadıysa, 
                    # metni direkt utf-8 olarak encode et (boşlukları korumak önemli)
                    if is_classic_algorithm and not found_label:
                        if all(c.isalpha() or c.isspace() or c in '.,!?;:-\'"()[]{}' for c in process_text):
                            data = process_text.encode('utf-8')
                        else:
                            # Yine de hex/base64 olabilir
                            text_clean = process_text.replace(" ", "").replace("\n", "").replace("\t", "").replace(":", "").replace("-", "")
                            try:
                                # Base64 dene
                                data = b64.b64decode(text_clean)
                            except:
                                try:
                                    # Hex dene
                                    data = bytes.fromhex(text_clean)
                                except:
                                    data = process_text.encode('utf-8')
                    else:
                        # Modern algoritmalar için: Boşlukları temizle ve hex/base64 parse et
                        text_clean = process_text.replace(" ", "").replace("\n", "").replace("\t", "").replace(":", "").replace("-", "")
                        
                        # Base64 kontrolü
                        try:
                            # 4'ün katı olmalı, değilse padding eksik olabilir (ama b64decode bazen halleder)
                            data = b64.b64decode(text_clean)
                            Logger.info(f"Metin Base64 olarak parse edildi.", "MainWindow")
                        except:
                            try:
                                # Hex kontrolü
                                data = bytes.fromhex(text_clean)
                                Logger.info(f"Metin Hex olarak parse edildi.", "MainWindow")
                            except:
                                # Son çare normal utf-8
                                data = process_text.encode('utf-8')
                                Logger.info(f"Metin UTF-8 olarak encode edildi.", "MainWindow")
                else:
                    # Şifreleme için normal encode
                    data = process_text.encode('utf-8')

                self.root.after(0, lambda: self.progress_var.set(50))
                
                # Mod bilgisini metadata'ya ekle
                use_library = self.implementation_mode_var.get() == 'library'
                metadata = {'use_library': use_library, 'impl_mode': 'library' if use_library else 'manual'}
                
                # Hibrit şifreleme kontrolü
                if algorithm.startswith("hybrid_"):
                        if operation == "DECRYPT":
                            response = self.client.send_hybrid_packet(data)
                        else:
                            # Hibrit şifreleme
                            packet_bytes, encrypted_message, encrypted_key = self._get_hybrid_packet(data, algorithm, metadata)
                        
                        # EKRANDA ÖNCE ŞİFRELİ HALİNİ GÖSTER (Kullanıcı "Şifrele" dediğinde bunu bekler)
                        import base64
                        c_text_b64 = base64.b64encode(encrypted_message).decode('utf-8')
                        k_text_b64 = base64.b64encode(encrypted_key).decode('utf-8')
                        
                        self.local_hybrid_result = f"🔐 YEREL ŞİFRELENMİŞ VERİ (Base64):\n{c_text_b64}\n\n🔑 ŞİFRELENMİŞ ANAHTAR (Base64):\n{k_text_b64}\n\n"
                        self.local_hybrid_result += f"📡 Paket server'a gönderildi, doğrulama bekleniyor..."
                        self.root.after(0, lambda: self._update_text_result(self.local_hybrid_result))

                        # Gönder
                        response = self.client.send_hybrid_packet(packet_bytes)
                else:
                    # Normal şifreleme
                    response = self.client.process_request(data, operation, algorithm, key, metadata)

                # Debug: Response'u logla
                if response:
                    Logger.info(f"Response alındı - Success: {response.get('success')}, Type: {response.get('type')}, Has Data: {bool(response.get('data'))}", "MainWindow")
                    if not response.get('success'):
                        Logger.warning(f"Response başarısız - Error: {response.get('error', 'N/A')}, Metadata: {response.get('metadata', {})}", "MainWindow")
                else:
                    Logger.error("Response None döndü!", "MainWindow")
                
                if response and response.get('success'):
                    result_data = response['data']
                    if operation == "ENCRYPT":
                        # RSA için özel format kontrolü (private key içerebilir)
                        if algorithm.lower() in ['rsa', 'rsa_manual']:
                            try:
                                result_str = result_data.decode('utf-8', errors='ignore')
                                # Private key varsa ayrı göster
                                if "RSA_PRIVATE_KEY:" in result_str:
                                    parts = result_str.split("ŞİFRELENMİŞ VERİ:")
                                    private_key_part = parts[0].replace("RSA_PRIVATE_KEY:", "").strip()
                                    encrypted_part = parts[1].strip() if len(parts) > 1 else ""
                                    
                                    import base64
                                    hex_result = result_data.hex()
                                    result_text = f"⚠️ ÖNEMLİ: Private Key'i kaydedin (deşifreleme için gerekli)!\n\nPrivate Key (Base64):\n{private_key_part}\n\nŞifrelenmiş Veri (Base64):\n{encrypted_part}\n\nŞifrelenmiş Veri (Hex):\n{hex_result}\n\nBoyut: {len(result_data)} byte"
                                else:
                                    # Normal RSA sonucu
                                    hex_result = result_data.hex()
                                    import base64
                                    base64_result = base64.b64encode(result_data).decode('utf-8')
                                    result_text = f"Şifrelenmiş Veri (Hex):\n{hex_result}\n\nŞifrelenmiş Veri (Base64):\n{base64_result}\n\nBoyut: {len(result_data)} byte"
                            except:
                                hex_result = result_data.hex()
                                import base64
                                base64_result = base64.b64encode(result_data).decode('utf-8')
                                result_text = f"Şifrelenmiş Veri (Hex):\n{hex_result}\n\nBase64 Formatı:\n{base64_result}"
                        else:
                            # Şifrelenmiş veri binary olduğu için hex formatında göster
                            hex_result = result_data.hex()
                            # Base64 formatı da ekle (alternatif)
                            import base64
                            base64_result = base64.b64encode(result_data).decode('utf-8')
                            
                            # AES/DES/IDEA/IRON gibi modern algoritmalar için detaylı göster
                            if algorithm.lower() in ['aes', 'des', 'aes_manual', 'des_manual', 'rsa', 'rsa_manual', 'aes_lib', 'des_lib', 'rsa_lib', 'idea', 'iron']:
                                result_text = f"Şifrelenmiş Veri (Hex):\n{hex_result}\n\nŞifrelenmiş Veri (Base64):\n{base64_result}\n\nBoyut: {len(result_data)} byte"
                            else:
                                # Klasik algoritmalar için sadece metni göster (kullanıcı isteği)
                                try:
                                    text_result = result_data.decode('utf-8', errors='ignore')
                                    result_text = text_result
                                except:
                                    result_text = hex_result
                    else:
                        # Çözme işlemi için düz metin göster
                        try:
                            result_text = result_data.decode('utf-8', errors='ignore')
                        except Exception as decode_error:
                            # Decode edilemezse hex olarak göster
                            result_text = result_data.hex()

                    self.root.after(0, lambda: self.progress_var.set(100))
                    
                    # Hibrit işlemlerde özel mesaj göster
                    if algorithm.startswith("hybrid_"):
                        try:
                            decoded_result = result_data.decode('utf-8', errors='ignore')
                            self.root.after(0, lambda: messagebox.showinfo("Hibrit Başarılı", f"Paket gönderildi ve server tarafından başarıyla çözüldü!\n\nÇözülen Metin: {decoded_result[:50]}..."))
                            
                            # Mevcut şifreli sonucu koru, üzerine "DOĞRULANDI" ekle
                            if hasattr(self, 'local_hybrid_result'):
                                result_text = self.local_hybrid_result.replace("📡 Paket server'a gönderildi, doğrulama bekleniyor...", "✅ SERVER DOĞRULAMASI BAŞARILI!")
                                result_text += f"\n\n🔓 SERVER TARAFINDAN ÇÖZÜLEN METİN:\n{decoded_result}"
                            else:
                                result_text = f"✅ SERVER TARAFINDAN ÇÖZÜLEN METİN:\n{decoded_result}"
                        except:
                            result_text = f"✅ Paket server tarafından başarıyla çözüldü (Binary)."
                    
                    self.root.after(0, lambda: self._update_text_result(result_text))
                else:
                    error_msg = "İşlem başarısız."
                    if response:
                        # Önce direkt error alanını kontrol et
                        if 'error' in response:
                            error_msg = response['error']
                        # Sonra metadata'dan error'u kontrol et
                        elif 'metadata' in response and 'error' in response['metadata']:
                            error_msg = response['metadata']['error']
                        # ERROR paket tipi kontrolü
                        elif 'type' in response and response['type'] == 'ERROR':
                            if 'metadata' in response and 'error' in response['metadata']:
                                error_msg = response['metadata']['error']
                            else:
                                error_msg = "Server hatası: Bilinmeyen hata"
                        # Genel başarısız durum
                        elif not response.get('success', False):
                            error_msg = "İşlem başarısız oldu. Lütfen tekrar deneyin."
                    
                    # Bağlantı hatası için özel mesaj
                    if 'bağlan' in error_msg.lower() or 'connection' in error_msg.lower() or 'server' in error_msg.lower():
                        error_msg += "\n\nÇözüm önerileri:\n1. Server'ın çalıştığından emin olun\n2. Server IP ve port bilgilerini kontrol edin\n3. Firewall ayarlarını kontrol edin"
                    
                    self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))

                self.root.after(0, lambda: self.progress_var.set(0))
                self.root.after(0, lambda: self.process_button.config(state="normal", text="İşlemi Başlat"))

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Hata", f"İşlem hatası: {str(e)}"))
                self.root.after(0, lambda: self.progress_var.set(0))
                self.root.after(0, lambda: self.process_button.config(state="normal", text="İşlemi Başlat"))

        threading.Thread(target=process_thread, daemon=True).start()

    def _process_file(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Uyarı", "Lütfen geçerli bir dosya seçin.")
            return

        if not self.client or not self.client.is_connected():
            messagebox.showerror("Hata", "Server bağlantısı yok.")
            return

        operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
        algorithm = self.algorithm_var.get()
        key = self.key_var.get().strip()

        # Şifrelemede anahtar boş veya otomatik ise üret
        if operation == "ENCRYPT":
            if not key or "OTOMATİK" in key.upper():
                if algorithm == "pigpen" or algorithm == "polybius":
                    key = ""
                else:
                    key = self._generate_random_key(algorithm)
                    self.key_var.set(key)
        else:
            # Çözmede anahtar boş olamaz
            if not key and algorithm not in ["pigpen", "polybius"]:
                messagebox.showwarning("Uyarı", "Lütfen deşifreleme anahtarını girin.")
                return

        if not self._validate_key(key):
            messagebox.showerror("Hata", "Geçersiz anahtar formatı.")
            return

        def process_thread():
            try:
                self.root.after(0, lambda: self.file_progress_var.set(10))
                self.root.after(0, lambda: self.file_process_button.config(state="disabled", text="İşleniyor..."))
                
                with open(file_path, 'rb') as f:
                    file_data = f.read()

                self.root.after(0, lambda: self.file_progress_var.set(30))

                operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
                algorithm = self.algorithm_var.get()
                
                key = self.key_var.get()
                
                # Pigpen cipher ve Hibrit mod anahtar gerektirmez
                if algorithm != "pigpen" and not algorithm.startswith("hybrid_") and not key:
                    self.root.after(0, lambda: messagebox.showwarning("Uyarı", "Anahtar bulunamadı. Lütfen 'Şifrele' modunu seçin veya anahtar girin."))
                    self.root.after(0, lambda: self.file_progress_var.set(0))
                    self.root.after(0, lambda: self.file_process_button.config(state="normal", text="Dosyayı İşle"))
                    return

                # Mod bilgisini metadata'ya ekle
                use_library = self.implementation_mode_var.get() == 'library'
                metadata = {
                    'use_library': use_library, 
                    'impl_mode': 'library' if use_library else 'manual',
                    'filename': os.path.basename(file_path),
                    'extension': os.path.splitext(file_path)[1].lower(),
                    'file_size': len(file_data)
                }
                
                self.root.after(0, lambda: self.file_progress_var.set(50))
                
                if algorithm.startswith("hybrid_"):
                    if operation == "DECRYPT":
                        response = self.client.send_hybrid_packet(file_data)
                    else:
                         # Hibrit şifreleme
                        packet_bytes, encrypted_message, encrypted_key = self._get_hybrid_packet(file_data, algorithm, metadata)
                        
                        # DOSYA OLARAK KAYDEDİLECEK VERİ: TÜM PAKET (JSON)
                        self._hybrid_file_packet = packet_bytes
                        response = self.client.send_hybrid_packet(packet_bytes)
                else:    
                    response = self.client.process_request(file_data, operation, algorithm, key, metadata)
                
                self.root.after(0, lambda: self.file_progress_var.set(80))

                if response and response.get('success'):
                    # Hibrit şifrelemede result_data server'dan gelen plaintext'tir.
                    # Ama biz dosyayı ŞİFRELİ (Packet) olarak kaydetmek istiyoruz.
                    if algorithm.startswith("hybrid_") and operation == "ENCRYPT":
                        result_data = self._hybrid_file_packet
                    else:
                        result_data = response['data']
                    
                    self._current_file_result = result_data
                    
                    # Dosya bilgilerini hazırla
                    original_filename = os.path.basename(file_path)
                    original_name, original_ext = os.path.splitext(original_filename)
                    
                    if operation == "ENCRYPT":
                        # Şifreleme: dosya adına .enc ekle
                        encrypted_filename = original_name + original_ext + ".enc"
                        self._current_encrypted_filename = encrypted_filename
                        
                        # Otomatik olarak EncryptedFiles klasörüne kaydet
                        encrypted_files_dir = os.path.join("EncryptedFiles", "encrypted")
                        os.makedirs(encrypted_files_dir, exist_ok=True)
                        auto_save_path = os.path.join(encrypted_files_dir, encrypted_filename)
                        
                        try:
                            with open(auto_save_path, 'wb') as f:
                                f.write(result_data)
                            
                            # Metadata'yı da kaydet
                            metadata = {
                                'algorithm': algorithm,
                                'key': key,
                                'original_filename': original_filename,
                                'original_size': len(file_data),
                                'encrypted_size': len(result_data),
                                'operation': 'ENCRYPT'
                            }
                            self.file_manager.save_file(result_data, encrypted_filename, metadata)
                            
                            result_info = f"✅ Şifreleme tamamlandı!\n\n"
                            result_info += f"📁 Orijinal Dosya: {original_filename}\n"
                            result_info += f"📁 Şifreli Dosya: {encrypted_filename}\n"
                            result_info += f"💾 Otomatik Kayıt: {auto_save_path}\n"
                            result_info += f"🔐 Algoritma: {algorithm}\n"
                            result_info += f"🔑 Anahtar: {key}\n"
                            result_info += f"📊 Orijinal Boyut: {len(file_data):,} bytes\n"
                            result_info += f"📊 Şifreli Boyut: {len(result_data):,} bytes\n\n"
                            result_info += f"✅ Dosya otomatik olarak kaydedildi!\n"
                            result_info += f"💡 Farklı bir yere kaydetmek için 'Sonucu Kaydet' butonunu kullanabilirsiniz."
                        except Exception as e:
                            result_info = f"✅ Şifreleme tamamlandı!\n\n"
                            result_info += f"📁 Orijinal Dosya: {original_filename}\n"
                            result_info += f"📁 Şifreli Dosya: {encrypted_filename}\n"
                            result_info += f"🔐 Algoritma: {algorithm}\n"
                            result_info += f"🔑 Anahtar: {key}\n"
                            result_info += f"📊 Orijinal Boyut: {len(file_data):,} bytes\n"
                            result_info += f"📊 Şifreli Boyut: {len(result_data):,} bytes\n\n"
                            result_info += f"⚠️ Otomatik kayıt hatası: {str(e)}\n"
                            result_info += f"💾 Dosyayı kaydetmek için 'Sonucu Kaydet' butonuna tıklayın."
                    else:
                        # Deşifreleme: .enc uzantısını kaldır
                        if original_filename.endswith('.enc'):
                            decrypted_filename = original_filename[:-4]  # .enc'i kaldır
                        else:
                            decrypted_filename = original_name + original_ext
                        self._current_encrypted_filename = decrypted_filename
                        
                        # Otomatik olarak EncryptedFiles klasörüne kaydet
                        encrypted_files_dir = os.path.join("EncryptedFiles", "encrypted")
                        os.makedirs(encrypted_files_dir, exist_ok=True)
                        auto_save_path = os.path.join(encrypted_files_dir, decrypted_filename)
                        
                        try:
                            with open(auto_save_path, 'wb') as f:
                                f.write(result_data)
                            
                            # Metadata'yı da kaydet
                            metadata = {
                                'algorithm': algorithm,
                                'key': key,
                                'encrypted_filename': original_filename,
                                'decrypted_filename': decrypted_filename,
                                'encrypted_size': len(file_data),
                                'decrypted_size': len(result_data),
                                'operation': 'DECRYPT'
                            }
                            self.file_manager.save_file(result_data, decrypted_filename, metadata)
                            
                            result_info = f"✅ Deşifreleme tamamlandı!\n\n"
                            result_info += f"📁 Şifreli Dosya: {original_filename}\n"
                            result_info += f"📁 Çözülmüş Dosya: {decrypted_filename}\n"
                            result_info += f"💾 Otomatik Kayıt: {auto_save_path}\n"
                            result_info += f"🔐 Algoritma: {algorithm}\n"
                            result_info += f"🔑 Anahtar: {key}\n"
                            result_info += f"📊 Şifreli Boyut: {len(file_data):,} bytes\n"
                            result_info += f"📊 Orijinal Boyut: {len(result_data):,} bytes\n\n"
                            result_info += f"✅ Dosya otomatik olarak kaydedildi!\n"
                            result_info += f"💡 Farklı bir yere kaydetmek için 'Sonucu Kaydet' butonunu kullanabilirsiniz."
                        except Exception as e:
                            result_info = f"✅ Deşifreleme tamamlandı!\n\n"
                            result_info += f"📁 Şifreli Dosya: {original_filename}\n"
                            result_info += f"📁 Çözülmüş Dosya: {decrypted_filename}\n"
                            result_info += f"🔐 Algoritma: {algorithm}\n"
                            result_info += f"🔑 Anahtar: {key}\n"
                            result_info += f"📊 Şifreli Boyut: {len(file_data):,} bytes\n"
                            result_info += f"📊 Orijinal Boyut: {len(result_data):,} bytes\n\n"
                            result_info += f"⚠️ Otomatik kayıt hatası: {str(e)}\n"
                            result_info += f"💾 Dosyayı kaydetmek için 'Sonucu Kaydet' butonuna tıklayın."
                    
                    self.root.after(0, lambda: self.file_progress_var.set(100))
                    self.root.after(0, lambda: self._update_file_result(result_info))
                    self.root.after(0, lambda: self.file_process_button.config(state="normal", text="Dosyayı İşle"))
                else:
                    error_msg = "İşlem başarısız."
                    if response and 'metadata' in response:
                        error_msg = response['metadata'].get('error', error_msg)
                    self.root.after(0, lambda: self.file_progress_var.set(0))
                    self.root.after(0, lambda: self.file_process_button.config(state="normal", text="Dosyayı İşle"))
                    self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))

            except Exception as e:
                self.root.after(0, lambda: self.file_progress_var.set(0))
                self.root.after(0, lambda: self.file_process_button.config(state="normal", text="Dosyayı İşle"))
                self.root.after(0, lambda: messagebox.showerror("Hata", f"Dosya işleme hatası: {str(e)}"))

        threading.Thread(target=process_thread, daemon=True).start()

    def _select_file(self):
        file_path = filedialog.askopenfilename(
            title="Dosya Seçin",
            filetypes=[
                ("Tüm Dosyalar", "*.*"),
                ("Metin Dosyaları", "*.txt"),
                ("Resim Dosyaları", "*.png *.jpg *.jpeg"),
                ("Ses Dosyaları", "*.wav *.mp3"),
                ("Video Dosyaları", "*.mp4 *.avi")
            ]
        )

        if file_path:
            self.file_path_var.set(file_path)
            self._update_file_info(file_path)

    def _update_file_info(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            file_type = FileUtils.get_file_type(file_path)
            is_supported = FileUtils.is_supported_format(file_path)

            info_text = f"Dosya: {os.path.basename(file_path)}\n"
            info_text += f"Boyut: {file_size} bytes\n"
            info_text += f"Tip: {file_type}\n"
            info_text += f"Destekleniyor: {'Evet' if is_supported else 'Hayır'}"

            self.file_info_text.config(state=tk.NORMAL)
            self.file_info_text.delete("1.0", tk.END)
            self.file_info_text.insert("1.0", info_text)
            self.file_info_text.config(state=tk.DISABLED)

        except Exception as e:
            Logger.error(f"Dosya bilgi güncelleme hatası: {str(e)}", "MainWindow")

    def _update_text_result(self, result_text):
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert("1.0", result_text)
        self.text_output.config(state=tk.DISABLED)

    def _update_file_result(self, result_info):
        self.file_result_text.config(state=tk.NORMAL)
        self.file_result_text.delete("1.0", tk.END)
        self.file_result_text.insert("1.0", result_info)
        self.file_result_text.config(state=tk.DISABLED)

    def _save_text_result(self):
        result_text = self.text_output.get("1.0", tk.END).strip()
        if not result_text:
            messagebox.showwarning("Uyarı", "Kaydedilecek sonuç yok.")
            return

        filename = filedialog.asksaveasfilename(
            title="Sonucu Kaydet",
            defaultextension=".txt",
            filetypes=[("Metin Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(result_text)
                messagebox.showinfo("Başarılı", "Sonuç kaydedildi.")
            except Exception as e:
                messagebox.showerror("Hata", f"Kaydetme hatası: {str(e)}")

    def _copy_text_result(self):
        result_text = self.text_output.get("1.0", tk.END).strip()
        if result_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(result_text)
            messagebox.showinfo("Başarılı", "Sonuç panoya kopyalandı.")
        else:
            messagebox.showwarning("Uyarı", "Kopyalanacak sonuç yok.")
    
    def _copy_hex_result(self):
        """Sonuç alanından sadece hex string'i kopyalar."""
        try:
            result = self.text_output.get("1.0", tk.END).strip()
            
            # Hex Formatı: satırını bul
            if "Hex Formatı:" in result or "Hex Format:" in result:
                lines = result.split('\n')
                hex_line = None
                for i, line in enumerate(lines):
                    if "Hex Format" in line or "hex" in line.lower():
                        # Sonraki satır hex string olabilir
                        if i + 1 < len(lines):
                            hex_line = lines[i + 1].strip()
                            break
                        # Veya aynı satırda olabilir
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            hex_line = parts[1].strip()
                            break
                
                if hex_line:
                    # Hex string'i temizle
                    hex_clean = hex_line.replace(" ", "").replace("\n", "").replace("\t", "")
                    self.root.clipboard_clear()
                    self.root.clipboard_append(hex_clean)
                    messagebox.showinfo("Başarılı", f"Hex string panoya kopyalandı ({len(hex_clean)} karakter)")
                else:
                    messagebox.showwarning("Uyarı", "Hex string bulunamadı.")
            else:
                messagebox.showwarning("Uyarı", "Sonuç alanında hex formatı bulunamadı.")
        except Exception as e:
            messagebox.showerror("Hata", f"Kopyalama hatası: {str(e)}")

    def _save_file_result(self):
        if not hasattr(self, '_current_file_result'):
            messagebox.showwarning("Uyarı", "Kaydedilecek dosya sonucu yok.")
            return

        # Önerilen dosya adını kullan
        suggested_filename = ""
        if hasattr(self, '_current_encrypted_filename'):
            suggested_filename = self._current_encrypted_filename
        
        filename = filedialog.asksaveasfilename(
            title="Sonucu Kaydet",
            initialfile=suggested_filename,
            filetypes=[("Tüm Dosyalar", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self._current_file_result)
                messagebox.showinfo("Başarılı", f"Dosya kaydedildi:\n{filename}")
            except Exception as e:
                messagebox.showerror("Hata", f"Kaydetme hatası: {str(e)}")

    def _open_file_result(self):
        if not hasattr(self, '_current_file_result'):
            messagebox.showwarning("Uyarı", "Açılacak dosya sonucu yok.")
            return

        import tempfile
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(self._current_file_result)
        temp_file.close()

        os.startfile(temp_file.name)

    def _refresh_saved_files(self):
        try:
            for item in self.saved_files_tree.get_children():
                self.saved_files_tree.delete(item)

            files = self.file_manager.list_files()
            for file_info in files:
                if not file_info: continue
                metadata = file_info.get('metadata', {}) or {}
                algorithm = metadata.get('algorithm', 'Bilinmiyor')

                self.saved_files_tree.insert("", "end",
                    text=file_info['filename'],
                    values=(file_info['size'], file_info.get('file_type', 'Bilinmiyor'), algorithm)
                )

        except Exception as e:
            Logger.error(f"Kayıtlı dosyalar yenileme hatası: {str(e)}", "MainWindow")

    def _load_saved_file(self):
        selection = self.saved_files_tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin.")
            return

        item = self.saved_files_tree.item(selection[0])
        filename = item['text']

        try:
            data = self.file_manager.load_file(filename)
            if data:
                try:
                    text_data = data.decode('utf-8')
                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert("1.0", text_data)
                    self.notebook.select(0)
                except UnicodeDecodeError:
                    messagebox.showinfo("Bilgi", "Dosya metin formatında değil. Dosya işleme sekmesini kullanın.")
            else:
                messagebox.showerror("Hata", "Dosya yüklenemedi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya yükleme hatası: {str(e)}")

    def _delete_saved_file(self):
        selection = self.saved_files_tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin.")
            return

        item = self.saved_files_tree.item(selection[0])
        filename = item['text']

        if messagebox.askyesno("Onay", f"'{filename}' dosyasını silmek istediğinizden emin misiniz?"):
            if self.file_manager.delete_file(filename):
                messagebox.showinfo("Başarılı", "Dosya silindi.")
                self._refresh_saved_files()
            else:
                messagebox.showerror("Hata", "Dosya silinemedi.")

    def _show_file_info(self):
        selection = self.saved_files_tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin.")
            return

        item = self.saved_files_tree.item(selection[0])
        filename = item['text']

        try:
            file_info = self.file_manager.get_file_info(filename)
            if file_info:
                info_text = f"Dosya: {file_info['filename']}\n"
                info_text += f"Boyut: {file_info['size']} bytes\n"
                info_text += f"Tip: {file_info['file_type']}\n"
                info_text += f"Destekleniyor: {'Evet' if file_info['is_supported'] else 'Hayır'}\n"

                metadata = file_info.get('metadata', {})
                if metadata:
                    info_text += f"\nMetadata:\n"
                    for key, value in metadata.items():
                        info_text += f"  {key}: {value}\n"

                messagebox.showinfo("Dosya Bilgileri", info_text)
            else:
                messagebox.showerror("Hata", "Dosya bilgileri alınamadı.")
        except Exception as e:
            messagebox.showerror("Hata", f"Bilgi alma hatası: {str(e)}")

    def _clear_all(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete("1.0", tk.END)
        self.text_output.config(state=tk.DISABLED)
        self.file_path_var.set("")
        self.file_info_text.config(state=tk.NORMAL)
        self.file_info_text.delete("1.0", tk.END)
        self.file_info_text.config(state=tk.DISABLED)
        self.file_result_text.config(state=tk.NORMAL)
        self.file_result_text.delete("1.0", tk.END)
        self.file_result_text.config(state=tk.DISABLED)
        if hasattr(self, '_current_file_result'):
            delattr(self, '_current_file_result')

    def _on_algorithm_changed(self, event=None):
        """Algoritma değiştiğinde çağrılır."""
        algorithm = self.algorithm_var.get()
        key_info = self._get_algorithm_key_info(algorithm)

        if hasattr(self, 'key_info_label'):
            self.key_info_label.config(text=key_info)

        if hasattr(self, 'file_key_info_label'):
            self.file_key_info_label.config(text=key_info)
        
        # AES ve DES için mod seçimini güncelle
        if algorithm in ['aes', 'aes_manual', 'des', 'des_manual']:
            # Manuel algoritma seçildiyse mod'u manuel yap
            if algorithm.endswith('_manual'):
                self.implementation_mode_var.set('manual')
            else:
                self.implementation_mode_var.set('library')
        
        self._on_operation_changed()
    
    def _on_mode_changed(self, event=None):
        """Kütüphane/Manuel mod değiştiğinde çağrılır."""
        mode = self.implementation_mode_var.get()
        algorithm = self.algorithm_var.get()
        
        # AES için
        if algorithm == 'aes' or algorithm == 'aes_manual':
            if mode == 'manual':
                self.algorithm_var.set('aes_manual')
            else:
                self.algorithm_var.set('aes')
        
        # DES için
        elif algorithm == 'des' or algorithm == 'des_manual':
            if mode == 'manual':
                self.algorithm_var.set('des_manual')
            else:
                self.algorithm_var.set('des')
        
        # IDEA için
        elif algorithm == 'idea' :
            self.algorithm_var.set('idea')

        # Algoritma bilgisini güncelle
        self._on_algorithm_changed()

    def _on_operation_changed(self):
        """İşlem tipi değiştiğinde çağrılır."""
        operation = self.operation_var.get()
        algorithm = self.algorithm_var.get()
        
        # Hibrit modda anahtar girişi her zaman kapalıdır
        if algorithm.startswith("hybrid_"):
            self.key_entry.config(state='disabled')
            self.file_key_entry.config(state='disabled')
            self.key_var.set("OTOMATİK (Session Key)")
            return

        if operation == "encrypt":
            # Şifrelemede anahtar girişi kapalı (Random kuralı)
            self.key_entry.config(state='disabled')
            self.file_key_entry.config(state='disabled')
            self.key_var.set("OTOMATİK ÜRETİLECEK")
        else:
            # Çözmede anahtar girişi açık (Pasted key)
            self.key_entry.config(state='normal')
            self.file_key_entry.config(state='normal')
            if "OTOMATİK" in self.key_var.get():
                self.key_var.set("")

    def _generate_random_key(self, algorithm: str) -> str:
        """Her algoritma için uygun formatta rastgele anahtar üretir."""
        import random, string
        
        if algorithm == "caesar":
            return str(random.randint(1, 25))
        elif algorithm == "vigenere":
            return "".join(random.choices(string.ascii_uppercase, k=8))
        elif algorithm == "affine":
            a_list = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
            return f"{random.choice(a_list)},{random.randint(0, 25)}"
        elif algorithm == "hill":
            # Determinantı 26 ile aralarında asal olan basit rastgele matrisler
            safe_hills = ["3,3,2,5", "9,7,1,2", "5,8,17,3"]
            return random.choice(safe_hills)
        elif algorithm == "playfair":
            return "".join(random.choices(string.ascii_uppercase, k=10)).replace('J', 'I')
        elif algorithm == "railfence":
            return str(random.randint(2, 6))
        elif algorithm == "columnar":
            return "".join(random.choices(string.ascii_uppercase, k=7))
        elif algorithm == "polybius":
            return ""
        elif algorithm == "substitution":
            alphabet = list(string.ascii_uppercase)
            random.shuffle(alphabet)
            return "".join(alphabet)
        elif algorithm == "route":
            return f"4:4:{random.choice(['spiral', 'row', 'column', 'diagonal'])}"
        elif algorithm in ["aes", "aes_manual", "aes_lib", "idea"]:
            return "".join(random.choices(string.ascii_letters + string.digits, k=16))
        elif algorithm in ["des", "des_manual", "des_lib"]:
            return "".join(random.choices(string.ascii_letters + string.digits, k=8))
        elif algorithm == "iron":
            return "".join(random.choices(string.ascii_letters + string.digits, k=16))
        elif algorithm in ["rsa", "rsa_manual", "rsa_lib"]:
            return "generate"
        return "random_key_123"

    def _get_algorithm_key_info(self, algorithm: str) -> str:

        key_infos = {
            "caesar": "1-999 arası sayı (örn: 3)",
            "vigenere": "Alfabetik karakterler (örn: KEY)",
            "hill": "2x2: 1,2,3,4 veya 3x3: 1,2,3,4,5,6,7,8,9",
            "playfair": "Anahtar kelime (J hariç, örn: MONARCHY)",
            "railfence": "Ray sayısı 2-10 arası (örn: 3)",
            "columnar": "Anahtar kelime (örn: KEYWORD)",
            "polybius": "Tablo düzeni anahtarı (opsiyonel)",
            "substitution": "26 harflik alfabe karışımı (örn: 'QWERTYUIOPASDFGHJKLZXCVBNM')",
            "route": "Format: 'rows:cols:route_type' (örn: '3:3:spiral', '4:4:row')",
            "pigpen": "Anahtar gerekmez (otomatik sembol tablosu)",
            "aes": "16 byte anahtar (örn: 'my_secret_key16') - Kütüphaneli",
            "aes_manual": "16 byte anahtar (örn: 'my_secret_key16') - Kütüphanesiz",
            "des": "8 byte anahtar (örn: 'mykey123') - Kütüphaneli",
            "des_manual": "8 byte anahtar (örn: 'mykey123') - Kütüphanesiz",
            "idea": "16 byte anahtar (örn: 'my_secret_key16') - Kütüphaneli",
            "iron": "16 byte anahtar (örn: 'iron_key_1234567')",
            "rsa": "RSA anahtar çifti (otomatik üretilir)"
        }
        return key_infos.get(algorithm, "")

    def _show_algorithm_info(self):
        """Algoritma hakkında detaylı bilgi gösterir."""
        algorithm = self.algorithm_var.get()

        algorithm_descriptions = {
            "caesar": """CAESAR ŞİFRELEME
Klasik kaydırma tabanlı şifreleme algoritması.

Çalışma Prensibi:
- Her harf alfabede belirli bir sayı kadar kaydırılır
- Örnek: Shift=3 ise, 'A' → 'D', 'B' → 'E'
- Sadece harfleri şifreler (A-Z, a-z)
- Diğer karakterler (rakam, noktalama) değişmez

Güvenlik: Düşük (26 farklı anahtar)""",

            "vigenere": """VIGENÈRE ŞİFRELEME
Anahtar kelime tabanlı çoklu kaydırma şifrelemesi.

Çalışma Prensibi:
- Anahtar kelime tekrarlanarak kullanılır
- Her harf için farklı kaydırma miktarı uygulanır
- Caesar şifrelemenin gelişmiş versiyonu
- Anahtar uzunluğu kadar farklı Caesar şifresi kullanılır

Güvenlik: Orta (anahtar uzunluğuna bağlı)""",

            "affine": """AFFINE ŞİFRELEME
Doğrusal şifreleme algoritması.

Çalışma Prensibi:
- Her harf (ax + b) mod 26 formülü ile şifrelenir
- a: Anahtar çarpanı (1-25, 26 ile aralarında asal)
- b: Anahtar kaydırma (0-25)
- x: Orijinal harf pozisyonu (0-25)

Güvenlik: Düşük (312 farklı anahtar çifti)""",

            "hill": """HILL ŞİFRELEME
Matris tabanlı şifreleme algoritması.

Çalışma Prensibi:
- Metin bloklar halinde matrislere dönüştürülür
- C = K × P mod 26 (C: şifreli, K: anahtar matris, P: düz metin)
- 2x2 veya 3x3 matris kullanılır
- Matris determinantı 26 ile aralarında asal olmalı

Güvenlik: Orta (matris boyutuna bağlı)""",

            "playfair": """PLAYFAIR ŞİFRELEME
5x5 matris tabanlı çift karakter şifreleme.

Çalışma Prensibi:
- 5x5 matris oluşturulur (J genellikle I ile birleştirilir)
- Metin çift karakterler halinde işlenir
- Özel kurallara göre karakterler değiştirilir

Güvenlik: Düşük-Orta""",

            "railfence": """RAIL FENCE ŞİFRELEME
Zikzak desen tabanlı aktarım şifrelemesi.

Çalışma Prensibi:
- Metin zikzak desenle yazılır (ray sayısı kadar)
- Satırlar sırayla okunarak şifreli metin oluşturulur
- Sadece karakterlerin yeri değişir, karakterler değişmez

Güvenlik: Çok düşük""",

            "columnar": """COLUMNAR TRANSPOSITION
Sütunlu kaydırma tabanlı aktarım şifrelemesi.

Çalışma Prensibi:
- Metin sütunlara yerleştirilir
- Anahtar kelimeye göre sütunlar yeniden sıralanır
- Sütunlar sırayla okunarak şifreli metin oluşturulur

Güvenlik: Düşük""",

            "polybius": """POLYBIUS ŞİFRELEME
5x5 tablo tabanlı satır/sütun şifrelemesi.

Çalışma Prensibi:
- 5x5 tablo oluşturulur (alfabe + bir karakter)
- Her harf satır ve sütun numarası ile temsil edilir
- Örnek: 'A' → '11', 'B' → '12'

Güvenlik: Çok düşük""",

            "substitution": """SUBSTITUTION ŞİFRELEME
Alfabe karıştırma tabanlı şifreleme.

Çalışma Prensibi:
- 26 harflik alfabe karışımı kullanılır
- Her harf, karışık alfabedeki karşılığı ile değiştirilir
- Örnek: 'QWERTYUIOPASDFGHJKLZXCVBNM' ile A→Q, B→W

Güvenlik: Düşük (frekans analizi ile kırılabilir)""",

            "route": """ROUTE ŞİFRELEME
Rota tabanlı matris şifrelemesi.

Çalışma Prensibi:
- Metin bir matrise yerleştirilir
- Belirli bir rota izlenerek okunur
- Rota tipleri: spiral, row, column, diagonal
- Örnek: 3x3 spiral ile 'HELLO' → farklı sıralama

Güvenlik: Çok düşük""",

            "pigpen": """PIGPEN ŞİFRELEME
Sembol tabanlı şifreleme (Masonik şifreleme).

Çalışma Prensibi:
- Her harf özel bir sembol ile temsil edilir
- Semboller geometrik şekillerden oluşur
- I ve J harfleri aynı sembolü paylaşır
- Görsel olarak farklı görünür

Güvenlik: Çok düşük (sadece görsel gizlilik)""",

            "aes": """AES (ADVANCED ENCRYPTION STANDARD)
Modern simetrik blok şifreleme algoritması (Kütüphaneli).

Mimari: SPN (Substitution-Permutation Network) - Feistel olmayan

Özellikler:
- Blok Boyutu: 128 bit (16 byte)
- Anahtar Boyutu: 128, 192, 256 bit
- Tur Sayısı: 10 (AES-128), 12 (AES-192), 14 (AES-256)

Şifreleme Adımları:
1. Initial AddRoundKey
2. 9 Ara Tur: SubBytes → ShiftRows → MixColumns → AddRoundKey
3. Final Tur: SubBytes → ShiftRows → AddRoundKey (MixColumns yok)

Güvenlik: Çok yüksek (günümüz standardı)""",

            "aes_manual": """AES-128 MANUEL İMPLEMENTASYON
Kütüphanesiz manuel AES implementasyonu (Eğitim amaçlı).

Aynı AES algoritması, ancak kütüphane kullanmadan kodlanmış.
S-Box, ShiftRows, MixColumns, AddRoundKey adımları manuel olarak uygulanır.

Eğitim Değeri: Yüksek (algoritmanın iç yapısını anlamak için)""",

            "des": """DES (DATA ENCRYPTION STANDARD)
Klasik simetrik blok şifreleme algoritması (Kütüphaneli).

Mimari: Feistel Ağı

Özellikler:
- Blok Boyutu: 64 bit (8 byte)
- Anahtar Boyutu: 64 bit (56 bit efektif)
- Tur Sayısı: 16

Şifreleme Adımları:
1. Initial Permutation (IP)
2. 16 Tur: Li = Ri-1, Ri = Li-1 XOR F(Ri-1, Ki)
3. Yarımların yer değiştirmesi
4. Final Permutation (IP^-1)

Güvenlik: Düşük (56 bit anahtar yetersiz)""",

            "des_manual": """DES MANUEL İMPLEMENTASYON
Kütüphanesiz manuel DES implementasyonu (Eğitim amaçlı).

Aynı DES algoritması, ancak kütüphane kullanmadan kodlanmış.
IP, F fonksiyonu, S-Box, P-Box adımları manuel olarak uygulanır.

Eğitim Değeri: Yüksek (Feistel yapısını anlamak için)""",

            "rsa": """RSA (RIVEST–SHAMIR–ADLEMAN)
Asimetrik şifreleme algoritması (Kütüphaneli).

Tür: Asimetrik (Açık Anahtarlı) Şifreleme

Özellikler:
- Temel: Büyük tam sayıları çarpanlarına ayırmanın zorluğu
- Anahtar Çifti: Public Key (e, n) ve Private Key (d, n)
- Kullanım: Anahtar dağıtımı, dijital imzalar

Anahtar Üretimi:
1. İki asal sayı seç (p, q)
2. n = p × q
3. φ(n) = (p-1)(q-1)
4. e seç (genellikle 65537)
5. d = e^-1 mod φ(n)

Şifreleme: C = M^e mod n
Deşifreleme: M = C^d mod n

Güvenlik: Yüksek (anahtar boyutuna bağlı)""",

            "rsa_manual": """RSA MANUEL İMPLEMENTASYON
Kütüphanesiz manuel RSA implementasyonu (Eğitim amaçlı).

Aynı RSA algoritması, ancak kütüphane kullanmadan kodlanmış.
Miller-Rabin asallık testi, Extended Euclidean algoritması manuel olarak uygulanır.

Eğitim Değeri: Yüksek (asimetrik şifrelemenin matematiksel temellerini anlamak için)""",

            "idea": """IDEA (INTERNATIONAL DATA ENCRYPTION ALGORITHM)
Modern simetrik blok şifreleme algoritması (Kütüphaneli).

Mimari: Karıştırma ve Yayılma (Substitution-Permutation benzeri)

Özellikler:
- Blok Boyutu: 64 bit (8 byte)
- Anahtar Boyutu: 128 bit (16 byte)
- Tur Sayısı: 8.5 Tur
- İşlemler: XOR, Mod 2^16 toplama, Mod (2^16 + 1) çarpma

Güvenlik: Yüksek (Brute-force'a dayanıklı)""",

            "idea_manual": """IDEA MANUEL İMPLEMENTASYON
Kütüphanesiz manuel IDEA implementasyonu (Eğitim amaçlı).

8.5 turlu yapı, modular multiplication (mod 65537) ve key schedule manuel olarak kodlanmıştır.

Eğitim Değeri: Yüksek""",

            "aes_lib": "Kütüphane tabanlı AES (AES ile aynıdır).",
            "des_lib": "Kütüphane tabanlı DES (DES ile aynıdır).",
            "rsa_lib": "Kütüphane tabanlı RSA (RSA ile aynıdır).",

            "iron": """IRON (INTERNATIONAL DATA ENCRYPTION ALGORITHM - FEISTEL)
Modern simetrik blok şifreleme algoritması (Feistel mimarisi).

Mimari: Feistel Network

Özellikler:
- Blok Boyutu: 64 bit (8 byte)
- Anahtar Boyutu: 128 bit (16 byte)
- Tur Sayısı: Anahtar bağımlı (16 veya 17 tur)
- S-Box: Anahtar bağımlı dinamik üretilen 4 adet 8x32 kutu

Güvenlik: Yüksek (Dinamik yapısı sayesinde brute-force ve analiz saldırılarına dirençli)"""
        }

        description = algorithm_descriptions.get(algorithm, "Bilinmeyen algoritma")
        messagebox.showinfo(f"{algorithm.upper()} Algoritması", description)

    def _validate_key(self, key: str) -> bool:
        """Anahtarın seçilen algoritma için uygun formatta olup olmadığını kontrol eder."""
        algorithm = self.algorithm_var.get()

        if algorithm.startswith("hybrid_") or "OTOMATİK" in key.upper():
            return True

        if algorithm == "caesar":
            try:
                shift = int(key)
                return 1 <= shift <= 999
            except ValueError:
                return False

        elif algorithm == "vigenere":
            return bool(key) and any(c.isalpha() for c in key) and len(key) <= 50

        elif algorithm == "hill":
            try:
                key_values = [int(x.strip()) for x in key.split(',')]
                return len(key_values) in [4, 9]
            except ValueError:
                return False

        elif algorithm == "playfair":
            return bool(key) and len(key) <= 25 and all(c.isalpha() or c.isspace() for c in key)

        elif algorithm == "railfence":
            try:
                rails = int(key)
                return 2 <= rails <= 10
            except ValueError:
                return False

        elif algorithm == "columnar":
            return bool(key) and len(key) <= 20

        elif algorithm == "polybius":
            return True

        elif algorithm == "substitution":
            # 26 harflik alfabe karışımı kontrolü
            if not key or len(key) != 26:
                return False
            # Tüm harflerin farklı olup olmadığını kontrol et
            return len(set(key.upper())) == 26 and key.replace(' ', '').isalpha()

        elif algorithm == "route":
            # Format: rows:cols:route_type
            try:
                parts = key.split(':')
                if len(parts) != 3:
                    return False
                rows = int(parts[0])
                cols = int(parts[1])
                route_type = parts[2].lower()
                return rows >= 2 and cols >= 2 and route_type in ['spiral', 'row', 'column', 'diagonal']
            except (ValueError, IndexError):
                return False

        elif algorithm == "pigpen":
            # Anahtar gerekmez
            return True

        elif algorithm in ["aes", "aes_manual"]:
            if not key:
                return False
            try:
                parts = key.split(':', 2)
                if len(parts) == 1:
                    # Sadece key string
                    return len(key) >= 8
                elif len(parts) == 3:
                    # format: key_size:mode:key
                    size_str = parts[0].upper().replace("AES-", "").replace("AES", "")
                    key_size = int(size_str)
                    mode = parts[1].upper()
                    key_val = parts[2]
                    return key_size in [128, 192, 256] and mode in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM'] and len(key_val) >= 8
                return False
            except ValueError:
                return False

        elif algorithm in ["des", "des_manual"]:
            if not key:
                return False
            try:
                parts = key.split(':', 2)
                if len(parts) == 1:
                    return len(key) >= 8
                elif len(parts) == 2:
                    # format: mode:key
                    mode = parts[0].upper()
                    key_val = parts[1]
                    return mode in ['ECB', 'CBC', 'CFB', 'OFB'] and len(key_val) >= 8
                elif len(parts) == 3:
                    # format: DES:mode:key
                    mode = parts[1].upper()
                    key_val = parts[2]
                    return mode in ['ECB', 'CBC', 'CFB', 'OFB'] and len(key_val) >= 8
                return False
            except ValueError:
                return False

        elif algorithm in ["idea"]:
             if not key:
                return False
             try:
                parts = key.split(':', 2)
                if len(parts) == 1:
                    return len(key) >= 8
                elif len(parts) == 2:
                    mode = parts[0].upper()
                    key_val = parts[1]
                    return mode in ['ECB', 'CBC', 'CFB', 'OFB'] and len(key_val) >= 8
                return False
             except ValueError:
                return False

        elif algorithm == "iron":
            return bool(key) and len(key) >= 1

        elif algorithm in ["rsa", "rsa_manual"]:
            # RSA için 'generate' veya boş string kabul edilir
            return True

        elif algorithm == "affine":
            try:
                parts = key.split(',')
                if len(parts) != 2:
                    return False
                a = int(parts[0])
                b = int(parts[1])
                # a ve 26 aralarında asal olmalı
                import math
                return 1 <= a <= 25 and 0 <= b <= 25 and math.gcd(a, 26) == 1
            except ValueError:
                return False

        return False

    def _on_key_focus_in(self, event):

        algorithm = self.algorithm_var.get()
        placeholder_texts = {
            "caesar": "Örnek: 4",
            "vigenere": "Örnek: SECURITY",
            "affine": "Örnek: 7,3",
            "hill": "Örnek: 3,3,2,5",
            "playfair": "Örnek: CRYPTO",
            "railfence": "Örnek: 4",
            "columnar": "Örnek: COLUMN",
            "polybius": "Anahtar gerekmez",
            "substitution": "Örnek: MNBVCXZLKJHGFDSAPOIUYTREWQ",
            "route": "Örnek: 4:4:zigzag",
            "pigpen": "Anahtar gerekmez",
            "aes": "Örnek: 16byte_AES_key!",
            "aes_manual": "Örnek: 16byte_AES_key!",
            "des": "Örnek: DESkey12",
            "des_manual": "Örnek: DESkey12",
            "rsa": "Örnek: generate",
            "rsa_manual": "Örnek: generate",
            "idea": "Örnek: IDEA_KEY_128bit",
            "iron": "Örnek: IRON_KEY_128bit"
        }

        placeholder = placeholder_texts.get(algorithm, "")
        if placeholder and not self.key_var.get():
            self.key_var.set(placeholder)
            if hasattr(self, 'key_entry'):
                self.key_entry.config(foreground='gray')
            if hasattr(self, 'file_key_entry'):
                self.file_key_entry.config(foreground='gray')


    def _on_key_focus_out(self, event):

        if hasattr(self, 'key_entry'):
            self.key_entry.config(foreground='black')
        if hasattr(self, 'file_key_entry'):
            self.file_key_entry.config(foreground='black')


    def _fill_example_key(self):
        """Seçilen algoritmaya göre örnek anahtar girer."""

        algorithm = self.algorithm_var.get()

        example_keys = {
            # 🔐 Klasik Şifreleme
            "caesar": "4",
            "vigenere": "SECURITY",
            "affine": "7,3",                    # gcd(7,26)=1
            "hill": "3,3,2,5",                  # det=9 ≠ 0 mod 26
            "playfair": "CRYPTO",
            "railfence": "4",
            "columnar": "COLUMN",
            "polybius": "",
            "substitution": "MNBVCXZLKJHGFDSAPOIUYTREWQ",
            "route": "4:4:zigzag",
            "pigpen": "",

            # 🔒 Modern Simetrik
            "aes": "16byte_AES_key!",            # AES-128
            "aes_manual": "16byte_AES_key!",
            "des": "DESkey12",                   # 8 byte
            "des_manual": "DESkey12",

            # 🔑 Asimetrik
            "rsa": "generate",
            "rsa_manual": "generate",

            # 🧠 IDEA
            "idea": "IDEA_KEY_128bit",            # 16 byte / 128-bit

            # 🧪 IRON (özel)
            "iron": "IRON_KEY_128bit"
        }

        example_key = example_keys.get(algorithm, "")
            
        if example_key:
            self.key_var.set(example_key)
            messagebox.showinfo("Örnek Anahtar", f"Örnek anahtar girildi:\n{example_key}")
        else:
            messagebox.showinfo("Bilgi", "Bu algoritma için anahtar gerekmez.")


    def _on_key_validate(self, event):

        key = self.key_var.get().strip()
        algorithm = self.algorithm_var.get()

        if not key:
            if hasattr(self, 'key_status_label'):
                self.key_status_label.config(text="", foreground="red")
            return

        is_valid = self._validate_key(key)

        if hasattr(self, 'key_status_label'):
            if is_valid:
                self.key_status_label.config(text="✓ Geçerli anahtar", foreground="green")
            else:
                self.key_status_label.config(text="✗ Geçersiz anahtar formatı", foreground="red")

    def _show_about(self):
        about_text = "Kriptoloji Projesi\nŞifreleme/Çözme Sistemi\n\nPython + Tkinter + Socket tabanlı kriptoloji sistemi"
        messagebox.showinfo("Hakkında", about_text)

    def _show_decryption_help(self):
        """Deşifreleme işlemi için yardım mesajı gösterir"""
        help_text = """🔓 ŞİFRELENMİŞ DOSYAYI DEŞİFRELEME REHBERİ

📋 ADIM ADIM İŞLEM:

1️⃣  DOSYA SEÇİMİ
   • "Dosya Seç" butonuna tıklayın
   • Şifrelenmiş dosyayı seçin (örn: dosya.png.enc)
   • Dosya bilgileri otomatik gösterilir

2️⃣  İŞLEM TÜRÜNÜ SEÇİN
   • "Çöz" radio button'unu seçin
   • Bu işlem türünü DECRYPT olarak ayarlar

3️⃣  ALGORİTMA VE ANAHTAR GİRİN
   • Şifreleme sırasında kullanılan algoritmayı seçin
   • Şifreleme sırasında kullanılan anahtarı girin
   ⚠️  ÖNEMLİ: Algoritma ve anahtar şifreleme ile AYNI olmalı!

4️⃣  SERVER BAĞLANTISI
   • Server'a bağlı olduğunuzdan emin olun
   • Bağlantı yoksa "Bağlan" butonuna tıklayın

5️⃣  DEŞİFRELEME İŞLEMİ
   • "Dosyayı İşle" butonuna tıklayın
   • İşlem progress bar'da gösterilir
   • Server tarafında deşifreleme yapılır

6️⃣  SONUCU KAYDETME
   • Deşifrelenmiş dosya bilgileri gösterilir
   • "Sonucu Kaydet" butonuna tıklayın
   • Dosya adı otomatik önerilir (.enc uzantısı kaldırılır)

📌 ÖNEMLİ NOTLAR:

✅ Server ekranında şifreleme yapıldığında gösterilen bilgileri kaydedin:
   • Kullanılan Algoritma
   • Kullanılan Anahtar
   • Şifrelenmiş Dosya Adı

✅ Deşifreleme için bu bilgilerin TAMAMINI doğru girmeniz gerekir!

✅ Dosya türü önemli değildir (resim, ses, video, txt vb.)
   Tüm dosyalar binary olarak işlenir.

❌ Yanlış algoritma veya anahtar girerseniz deşifreleme başarısız olur!

💡 İPUCU: Server ekranındaki bilgileri kopyalayıp kullanabilirsiniz."""
        
        # Büyük bir pencere açmak için messagebox yerine Toplevel kullan
        help_window = tk.Toplevel(self.root)
        help_window.title("Deşifreleme Yardımı")
        help_window.geometry("700x650")
        help_window.resizable(True, True)
        
        # Scrollable text widget
        text_frame = ttk.Frame(help_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        help_text_widget = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=("Arial", 10))
        help_text_widget.pack(fill=tk.BOTH, expand=True)
        help_text_widget.insert("1.0", help_text)
        help_text_widget.config(state=tk.DISABLED)
        
        # Kapat butonu
        ttk.Button(help_window, text="Kapat", command=help_window.destroy).pack(pady=10)

    def _on_closing(self):
        if self.client:
            self.client.disconnect()
        self.root.destroy()

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.root.mainloop()
    def _get_hybrid_packet(self, data: bytes, algorithm: str, metadata: Dict) -> Tuple[bytes, bytes, bytes]:
        """Hibrit paket oluşturur (ECC veya RSA otomatik seçer)."""
        target_algo = algorithm.replace("hybrid_", "")
        
        if "ecc" in algorithm:
            # ECC Hybrid
            target_algo = target_algo.replace("ecc_", "")
            encrypted_message, encrypted_key, algo_name = self.hybrid_manager.encrypt_message_ecc(
                message=data,
                symmetric_algo=target_algo
            )
            packet_bytes = self.hybrid_manager.create_hybrid_packet(
                encrypted_message, encrypted_key, algo_name, key_type='ECC', metadata=metadata
            )
        else:
            # RSA Hybrid
            packet_bytes, encrypted_message, encrypted_key = self.hybrid_manager.encrypt_and_package(
                message=data,
                algorithm=target_algo,
                use_manual="manual" in target_algo,
                metadata=metadata
            )
        
        return packet_bytes, encrypted_message, encrypted_key

    def _on_algorithm_changed(self, event=None):
        algo = self.algorithm_var.get()
        operation = self.operation_var.get()
        
        # Hibrit modda veya Şifreleme modunda anahtar girişini kapat
        if algo.startswith("hybrid_") or operation == "encrypt":
            self.key_entry.config(state="disabled")
            self.file_key_entry.config(state="disabled")
            
            if algo.startswith("hybrid_"):
                self.key_var.set("OTOMATİK (Session Key)")
            else:
                self.key_var.set("OTOMATİK ÜRETİLECEK")
                
            self.key_info_label.config(text="Otomatik üretilir")
            self.file_key_info_label.config(text="Otomatik üretilir")
        else:
            # Sadece Deşifreleme + Klasik modda aç
            self.key_entry.config(state="normal")
            self.file_key_entry.config(state="normal")
            if "OTOMATİK" in self.key_var.get():
                self.key_var.set("")
            self.key_info_label.config(text="")
            self.file_key_info_label.config(text="")
