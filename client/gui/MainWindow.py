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
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        self.client: Optional[Client] = None
        self.file_manager = FileManager()
        
        self.input_data = tk.StringVar()
        self.algorithm_var = tk.StringVar(value="caesar")
        self.key_var = tk.StringVar()
        self.operation_var = tk.StringVar(value="encrypt")
        self.server_status_var = tk.StringVar(value="Bağlantı yok")
        
        self._create_widgets()
        self._create_menu()
        
        self._connect_to_server()
    
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
        
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(status_frame, text="Server Durumu:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, textvariable=self.server_status_var)
        self.status_label.pack(side=tk.LEFT, padx=(5, 0))
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self._create_text_tab()
        
        self._create_file_tab()
        
        self._create_saved_files_tab()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Button(button_frame, text="Temizle", command=self._clear_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Yeniden Bağlan", command=self._reconnect_server).pack(side=tk.LEFT, padx=(0, 5))
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
        
        ttk.Label(settings_frame, text="Anahtar:").grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        ttk.Entry(settings_frame, textvariable=self.key_var, width=20).grid(row=0, column=3, sticky=tk.W)
        
        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var, 
                       value="encrypt").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var, 
                       value="decrypt").pack(side=tk.LEFT)
        
        ttk.Button(settings_frame, text="İşlemi Başlat", command=self._process_text).grid(row=2, column=0, pady=(10, 0))
        
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
        
        ttk.Label(settings_frame, text="Anahtar:").grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        ttk.Entry(settings_frame, textvariable=self.key_var, width=20).grid(row=0, column=3, sticky=tk.W)
        
        operation_frame = ttk.Frame(settings_frame)
        operation_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Radiobutton(operation_frame, text="Şifrele", variable=self.operation_var, 
                       value="encrypt").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(operation_frame, text="Çöz", variable=self.operation_var, 
                       value="decrypt").pack(side=tk.LEFT)
        
        ttk.Button(settings_frame, text="Dosyayı İşle", command=self._process_file).grid(row=2, column=0, pady=(10, 0))
        
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
            self.client = Client()
            if self.client.connect():
                self.server_status_var.set("Bağlı")
                self.status_label.config(foreground="green")
            else:
                self.server_status_var.set("Bağlantı hatası")
                self.status_label.config(foreground="red")
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def _reconnect_server(self):
        if self.client:
            self.client.disconnect()
        self._connect_to_server()
    
    def _process_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Uyarı", "Lütfen işlenecek metin girin.")
            return
        
        if not self.client or not self.client.is_connected():
            messagebox.showerror("Hata", "Server bağlantısı yok.")
            return
        
        def process_thread():
            try:
                operation = "ENCRYPT" if self.operation_var.get() == "encrypt" else "DECRYPT"
                algorithm = self.algorithm_var.get()
                key = self.key_var.get()
                
                if not key:
                    messagebox.showwarning("Uyarı", "Lütfen anahtar girin.")
                    return
                
                data = text.encode('utf-8')
                response = self.client.process_request(data, operation, algorithm, key)
                
                if response and response.get('success'):
                    result_data = response['data']
                    if operation == "ENCRYPT":
                        result_text = result_data.hex()  # Şifrelenmiş veri hex olarak göster
                    else:
                        result_text = result_data.decode('utf-8', errors='ignore')
                    
                    self.root.after(0, lambda: self._update_text_result(result_text))
                else:
                    error_msg = "İşlem başarısız."
                    if response and 'metadata' in response:
                        error_msg = response['metadata'].get('error', error_msg)
                    self.root.after(0, lambda: messagebox.showerror("Hata", error_msg))
                    
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Hata", f"İşlem hatası: {str(e)}"))
        
        threading.Thread(target=process_thread, daemon=True).start()
    
    def _process_file(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Uyarı", "Lütfen geçerli bir dosya seçin.")
            return
        
        if not self.client or not self.client.is_connected():
            messagebox.showerror("Hata", "Server bağlantısı yok.")
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
    
    def _show_about(self):
        about_text = """Kriptoloji Projesi v2.0
        
Şifreleme ve Çözme Sistemi

Desteklenen Algoritmalar:
• Caesar Cipher
• Vigenère Cipher  
• Hill Cipher
• Playfair Cipher
• Rail Fence Cipher
• Columnar Transposition
• Polybius Cipher

Desteklenen Dosya Formatları:
• Metin: .txt, .md, .py, .js, .html, .css
• Resim: .png, .jpg, .jpeg, .gif, .bmp
• Ses: .wav, .mp3, .flac, .aac
• Video: .mp4, .avi, .mkv, .mov
• Doküman: .pdf, .doc, .docx

Geliştirici: Hüseyin"""
        messagebox.showinfo("Hakkında", about_text)
    
    def _on_closing(self):
        if self.client:
            self.client.disconnect()
        self.root.destroy()
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.root.mainloop()

