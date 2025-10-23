"""
Ana GUI sınıfı - Kullanıcı arayüzü ve etkileşim yönetimi
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
from typing import Optional, Dict, Any
from client.network.Client import Client
from client.file.FileManager import FileManager
from shared.utils import FileUtils, Logger


class MainWindow:
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Kriptoloji Projesi - Şifreleme/Çözme Sistemi")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.client: Optional[Client] = None
        self.file_manager = FileManager()
        
        # Server bağlantı bilgileri
        self.server_host_var = tk.StringVar(value="localhost")
        self.server_port_var = tk.StringVar(value="12345")
        
        self.input_data = tk.StringVar()
        self.algorithm_var = tk.StringVar(value="caesar")
        self.key_var = tk.StringVar()
        self.operation_var = tk.StringVar(value="encrypt")
        self.server_status_var = tk.StringVar(value="Bağlantı yok")
        
        self._create_widgets()
        self._create_menu()
        
        # Başlangıçta algoritma bilgisini göster
        self._on_algorithm_changed()
        
        # Otomatik bağlantı yapma, kullanıcı manuel bağlansın
    
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
        
        # Server bağlantı ayarları
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
                                     values=["caesar", "vigenere", "hill", "playfair", "railfence", "columnar", "polybius"], state="readonly")
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
        
        # Anahtar açıklaması
        self.key_info_label = ttk.Label(settings_frame, text="", foreground="blue")
        self.key_info_label.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=(10, 0), pady=(10, 0))
        
        # Anahtar durumu göstergesi
        self.key_status_label = ttk.Label(settings_frame, text="", foreground="red")
        self.key_status_label.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))
        
        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var, 
                       value="encrypt").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var, 
                       value="decrypt").pack(side=tk.LEFT)
        
        self.process_button = ttk.Button(settings_frame, text="İşlemi Başlat", command=self._process_text)
        self.process_button.grid(row=4, column=0, pady=(10, 0))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(settings_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(10, 0), pady=(10, 0))
        
        ttk.Label(text_frame, text="Sonuç:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.text_output = scrolledtext.ScrolledText(text_frame, height=8, width=50, state=tk.DISABLED)
        self.text_output.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        result_button_frame = ttk.Frame(text_frame)
        result_button_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(result_button_frame, text="Sonucu Kaydet", command=self._save_text_result).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(result_button_frame, text="Sonucu Kopyala", command=self._copy_text_result).pack(side=tk.LEFT)
    
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
                                     values=["caesar", "vigenere", "hill", "playfair", "railfence", "columnar", "polybius"], state="readonly")
        algorithm_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        algorithm_combo.bind("<<ComboboxSelected>>", self._on_algorithm_changed)
        
        ttk.Button(settings_frame, text="Algoritma Bilgisi", command=self._show_algorithm_info).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(settings_frame, text="Örnek Anahtar", command=self._fill_example_key).grid(row=0, column=3, padx=(5, 0))
        
        ttk.Label(settings_frame, text="Anahtar:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.file_key_entry = ttk.Entry(settings_frame, textvariable=self.key_var, width=20)
        self.file_key_entry.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        self.file_key_entry.bind('<FocusIn>', self._on_key_focus_in)
        self.file_key_entry.bind('<FocusOut>', self._on_key_focus_out)
        self.file_key_entry.bind('<KeyRelease>', self._on_key_validate)
        
        # Anahtar açıklaması (dosya sekmesi için)
        self.file_key_info_label = ttk.Label(settings_frame, text="", foreground="blue")
        self.file_key_info_label.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=(10, 0), pady=(10, 0))
        
        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var, 
                       value="encrypt").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var, 
                       value="decrypt").pack(side=tk.LEFT)
        
        self.file_process_button = ttk.Button(settings_frame, text="Dosyayı İşle", command=self._process_file)
        self.file_process_button.grid(row=3, column=0, pady=(10, 0))
        
        # Progress bar (dosya sekmesi)
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
                    self.root.after(0, lambda: self.server_status_var.set(f"Bağlı ({host}:{port})"))
                    self.root.after(0, lambda: self.status_label.config(foreground="green"))
                    self.root.after(0, lambda: messagebox.showinfo("Başarılı", f"Server'a bağlandı: {host}:{port}"))
                else:
                    self.root.after(0, lambda: self.server_status_var.set("Bağlantı hatası"))
                    self.root.after(0, lambda: self.status_label.config(foreground="red"))
                    self.root.after(0, lambda: messagebox.showerror("Hata", f"Server'a bağlanılamadı: {host}:{port}"))
            except ValueError:
                self.root.after(0, lambda: messagebox.showerror("Hata", "Geçerli bir port numarası giriniz."))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Hata", f"Bağlantı hatası: {str(e)}"))
        
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
        """Server bağlantısını test et"""
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
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Uyarı", "Lütfen işlenecek metin girin.")
            return
        
        if not self.client or not self.client.is_connected():
            messagebox.showerror("Hata", "Server bağlantısı yok.")
            return
        
        # Anahtar doğrulama
        key = self.key_var.get().strip()
        if not key:
            messagebox.showwarning("Uyarı", "Lütfen anahtar girin.")
            return
        
        if not self._validate_key(key):
            messagebox.showerror("Hata", "Geçersiz anahtar formatı. Lütfen algoritma bilgilerini kontrol edin.")
            return
        
        def process_thread():
            try:
                # Progress bar'ı başlat
                self.root.after(0, lambda: self.progress_var.set(10))
                self.root.after(0, lambda: self.process_button.config(state="disabled", text="İşleniyor..."))
                
                operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
                algorithm = self.algorithm_var.get()
                key = self.key_var.get()
                
                if not key:
                    self.root.after(0, lambda: messagebox.showwarning("Uyarı", "Lütfen anahtar girin."))
                    return
                
                self.root.after(0, lambda: self.progress_var.set(30))
                data = text.encode('utf-8')
                
                self.root.after(0, lambda: self.progress_var.set(50))
                response = self.client.process_request(data, operation, algorithm, key)
                
                if response and response.get('success'):
                    result_data = response['data']
                    if operation == "ENCRYPT":
                        # Şifrelenmiş veriyi hem hex hem de metin olarak göster
                        try:
                            text_result = result_data.decode('utf-8', errors='ignore')
                            hex_result = result_data.hex()
                            result_text = f"Şifrelenmiş Metin:\n{text_result}\n\nHex Formatı:\n{hex_result}"
                        except:
                            result_text = f"Şifrelenmiş Veri (Hex):\n{result_data.hex()}"
                    else:
                        result_text = result_data.decode('utf-8', errors='ignore')
                    
                    self.root.after(0, lambda: self.progress_var.set(100))
                    self.root.after(0, lambda: self._update_text_result(result_text))
                else:
                    error_msg = "İşlem başarısız."
                    if response and 'metadata' in response:
                        error_msg = response['metadata'].get('error', error_msg)
                    self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))
                
                # Progress bar'ı sıfırla
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
        
        # Anahtar doğrulama
        key = self.key_var.get().strip()
        if not key:
            messagebox.showwarning("Uyarı", "Lütfen anahtar girin.")
            return
        
        if not self._validate_key(key):
            messagebox.showerror("Hata", "Geçersiz anahtar formatı. Lütfen algoritma bilgilerini kontrol edin.")
            return
        
        def process_thread():
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
                algorithm = self.algorithm_var.get()
                key = self.key_var.get()
                
                if not key:
                    messagebox.showwarning("Uyarı", "Lütfen anahtar girin.")
                    return
                
                response = self.client.process_request(file_data, operation, algorithm, key)
                
                if response and response.get('success'):
                    result_data = response['data']
                    self._current_file_result = result_data
                    
                    result_info = f"İşlem tamamlandı.\nBoyut: {len(result_data)} bytes"
                    self.root.after(0, lambda: self._update_file_result(result_info))
                else:
                    error_msg = "İşlem başarısız."
                    if response and 'metadata' in response:
                        error_msg = response['metadata'].get('error', error_msg)
                    self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))
                    
            except Exception as e:
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
    
    def _save_file_result(self):
        if not hasattr(self, '_current_file_result'):
            messagebox.showwarning("Uyarı", "Kaydedilecek dosya sonucu yok.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Sonucu Kaydet",
            filetypes=[("Tüm Dosyalar", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self._current_file_result)
                messagebox.showinfo("Başarılı", "Dosya kaydedildi.")
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
                metadata = file_info.get('metadata', {})
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
                    self.notebook.select(0)  # Metin sekmesine geç
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
        """Algoritma değiştiğinde anahtar açıklamasını güncelle"""
        algorithm = self.algorithm_var.get()
        key_info = self._get_algorithm_key_info(algorithm)
        
        # Metin sekmesi anahtar bilgisi
        if hasattr(self, 'key_info_label'):
            self.key_info_label.config(text=key_info)
        
        # Dosya sekmesi anahtar bilgisi
        if hasattr(self, 'file_key_info_label'):
            self.file_key_info_label.config(text=key_info)
    
    def _get_algorithm_key_info(self, algorithm: str) -> str:
        """Algoritma anahtar bilgilerini döndür"""
        key_infos = {
            "caesar": "1-999 arası sayı (örn: 3)",
            "vigenere": "Alfabetik karakterler (örn: KEY)",
            "hill": "2x2: 1,2,3,4 veya 3x3: 1,2,3,4,5,6,7,8,9",
            "playfair": "Anahtar kelime (J hariç, örn: MONARCHY)",
            "railfence": "Ray sayısı 2-10 arası (örn: 3)",
            "columnar": "Anahtar kelime (örn: KEYWORD)",
            "polybius": "Tablo düzeni anahtarı (opsiyonel)"
        }
        return key_infos.get(algorithm, "")
    
    def _show_algorithm_info(self):
        """Algoritma bilgilerini göster"""
        algorithm = self.algorithm_var.get()
        
        algorithm_descriptions = {
            "caesar": """Caesar Cipher
Klasik kaydırma tabanlı şifreleme.
Anahtar: 1-999 arası sayı
Örnek: "HELLO" + anahtar 3 = "KHOOR"
Matematik: C = (P + K) mod 26""",
            
            "vigenere": """Vigenère Cipher
Anahtar kelime tabanlı şifreleme.
Anahtar: Alfabetik karakterler
Örnek: "HELLO" + anahtar "KEY" = "RIJVS"
Matematik: C = (P + K) mod 26""",
            
            "hill": """Hill Cipher
Matris tabanlı şifreleme.
Anahtar: 2x2 veya 3x3 matris
Örnek: 2x2 matris [1,2,3,4]
Matematik: C = (K × P) mod 26""",
            
            "playfair": """Playfair Cipher
5x5 matris tabanlı çift karakter şifreleme.
Anahtar: Anahtar kelime (J hariç)
Örnek: "HELLO" → "HE LX LO"
Matematik: 5x5 matris kuralları""",
            
            "railfence": """Rail Fence Cipher
Zikzak desen tabanlı aktarım şifreleme.
Anahtar: Ray sayısı (2-10)
Örnek: 3 ray ile "HELLOWORLD"
Matematik: Zikzak düzenleme""",
            
            "columnar": """Columnar Transposition
Sütunlu kaydırma tabanlı aktarım şifreleme.
Anahtar: Anahtar kelime (sütun sırası)
Örnek: "HELLOWORLD" + "KEYWORD"
Matematik: Sütun sıralama""",
            
            "polybius": """Polybius Cipher
5x5 tablo tabanlı satır/sütun şifreleme.
Anahtar: Tablo düzeni (opsiyonel)
Örnek: "HELLO" → "23 15 31 31 34"
Matematik: Satır-sütun koordinatları"""
        }
        
        description = algorithm_descriptions.get(algorithm, "Bilinmeyen algoritma")
        messagebox.showinfo(f"{algorithm.upper()} Algoritması", description)
    
    def _validate_key(self, key: str) -> bool:
        """Anahtar formatını doğrula"""
        algorithm = self.algorithm_var.get()
        
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
            return True  # Polybius anahtar opsiyonel
        
        return False
    
    def _on_key_focus_in(self, event):
        """Anahtar girişi odaklandığında"""
        algorithm = self.algorithm_var.get()
        placeholder_texts = {
            "caesar": "Örnek: 3",
            "vigenere": "Örnek: KEY",
            "hill": "Örnek: 1,2,3,4",
            "playfair": "Örnek: MONARCHY",
            "railfence": "Örnek: 3",
            "columnar": "Örnek: KEYWORD",
            "polybius": "Opsiyonel"
        }
        
        placeholder = placeholder_texts.get(algorithm, "")
        if placeholder and not self.key_var.get():
            self.key_var.set(placeholder)
            if hasattr(self, 'key_entry'):
                self.key_entry.config(foreground='gray')
            if hasattr(self, 'file_key_entry'):
                self.file_key_entry.config(foreground='gray')
    
    def _on_key_focus_out(self, event):
        """Anahtar girişi odaktan çıktığında"""
        if hasattr(self, 'key_entry'):
            self.key_entry.config(foreground='black')
        if hasattr(self, 'file_key_entry'):
            self.file_key_entry.config(foreground='black')
    
    def _fill_example_key(self):
        """Örnek anahtar doldur"""
        algorithm = self.algorithm_var.get()
        example_keys = {
            "caesar": "3",
            "vigenere": "KEY",
            "hill": "1,2,3,5",
            "playfair": "MONARCHY",
            "railfence": "3",
            "columnar": "KEYWORD",
            "polybius": ""
        }
        
        example_key = example_keys.get(algorithm, "")
        self.key_var.set(example_key)
        
        if example_key:
            messagebox.showinfo("Örnek Anahtar", f"'{algorithm}' algoritması için örnek anahtar: {example_key}")
        else:
            messagebox.showinfo("Örnek Anahtar", f"'{algorithm}' algoritması için anahtar opsiyoneldir.")
    
    def _on_key_validate(self, event):
        """Anahtar girişi sırasında doğrulama"""
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
        about_text = """Kriptoloji Projesi v2.0
        
Şifreleme ve Çözme Sistemi

Desteklenen Algoritmalar:
• Caesar Cipher - Kaydırma tabanlı
• Vigenère Cipher - Anahtar kelime tabanlı
• Hill Cipher - Matris tabanlı
• Playfair Cipher - 5x5 matris tabanlı
• Rail Fence Cipher - Zikzak aktarım
• Columnar Transposition - Sütunlu kaydırma
• Polybius Cipher - Satır/sütun tabanlı

Desteklenen Dosya Formatları:
• Metin: .txt, .md, .py, .js, .html, .css
• Resim: .png, .jpg, .jpeg, .gif, .bmp
• Ses: .wav, .mp3, .flac, .aac
• Video: .mp4, .avi, .mkv, .mov
• Doküman: .pdf, .doc, .docx

Özellikler:
• Server-Client mimarisi
• Gerçek zamanlı şifreleme
• Dosya ve metin desteği
• Görsel algoritma bilgileri
• Güvenli veri transferi

Geliştirici: Hüseyin"""
        messagebox.showinfo("Hakkında", about_text)
    
    def _on_closing(self):
        if self.client:
            self.client.disconnect()
        self.root.destroy()
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.root.mainloop()

