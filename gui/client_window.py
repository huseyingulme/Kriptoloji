import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.client import EncryptionClient

class ClientWindow:
    def __init__(self, root):
        self.root = root
        self.client = EncryptionClient()
        self.current_file_path = None
        self.current_encrypted_data = None

        self.setup_window()
        self.create_widgets()

    def setup_window(self):
        self.root.title("Kriptoloji Client")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        style = ttk.Style()
        style.theme_use('clam')

        self.root.configure(bg='#f5f5f5')

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        try:
            if self.client.is_connected:
                self.client.disconnect()
        except:
            pass
        self.root.destroy()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, bg='#f5f5f5', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(
            main_frame,
            text="Kriptoloji Client",
            font=('Arial', 18, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        title_label.pack(pady=(0, 20))

        self.create_connection_panel(main_frame)

        content_frame = tk.Frame(main_frame, bg='#f5f5f5')
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        self.create_encryption_panel(content_frame)

        self.create_data_panel(content_frame)

        self.create_file_management_panel(content_frame)

        self.create_results_panel(main_frame)

    def create_connection_panel(self, parent):
        connection_frame = tk.LabelFrame(
            parent,
            text="Server Bağlantısı",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        connection_frame.pack(fill=tk.X, pady=(0, 10))

        connection_inner = tk.Frame(connection_frame, bg='#f5f5f5')
        connection_inner.pack(fill=tk.X, padx=15, pady=15)

        tk.Label(connection_inner, text="Host:", font=('Arial', 11), bg='#f5f5f5').pack(side=tk.LEFT)

        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = tk.Entry(connection_inner, textvariable=self.host_var, width=15, font=('Arial', 11))
        host_entry.pack(side=tk.LEFT, padx=(5, 15))

        tk.Label(connection_inner, text="Port:", font=('Arial', 11), bg='#f5f5f5').pack(side=tk.LEFT)

        self.port_var = tk.StringVar(value="8080")
        port_entry = tk.Entry(connection_inner, textvariable=self.port_var, width=8, font=('Arial', 11))
        port_entry.pack(side=tk.LEFT, padx=(5, 15))

        self.connection_button = tk.Button(
            connection_inner,
            text="Bağlan",
            command=self.connect_to_server,
            font=('Arial', 11, 'bold'),
            bg='#4CAF50',
            fg='white',
            relief=tk.FLAT,
            padx=20,
            pady=8
        )
        self.connection_button.pack(side=tk.LEFT, padx=(0, 15))

        self.connection_status = tk.Label(
            connection_inner,
            text="Bağlı değil",
            font=('Arial', 11, 'bold'),
            bg='#f5f5f5',
            fg='#f44336'
        )
        self.connection_status.pack(side=tk.LEFT)

    def create_encryption_panel(self, parent):
        encryption_frame = tk.LabelFrame(
            parent,
            text="Şifreleme Ayarları",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        encryption_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        tk.Label(encryption_frame, text="Algoritma:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.algorithm_var = tk.StringVar(value="caesar")
        algorithm_combo = ttk.Combobox(
            encryption_frame,
            textvariable=self.algorithm_var,
            values=["caesar", "vigenere", "affine", "substitution", "rail_fence"],
            state="readonly",
            font=('Arial', 11)
        )
        algorithm_combo.pack(fill=tk.X, padx=10, pady=(0, 10))
        algorithm_combo.bind('<<ComboboxSelected>>', self.on_algorithm_changed)

        self.params_frame = tk.Frame(encryption_frame, bg='#f5f5f5')
        self.params_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.create_caesar_params()

        tk.Label(encryption_frame, text="İşlem Türü:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.operation_var = tk.StringVar(value="encrypt")
        operation_frame = tk.Frame(encryption_frame, bg='#f5f5f5')
        operation_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Radiobutton(
            operation_frame,
            text="Şifrele",
            variable=self.operation_var,
            value="encrypt",
            font=('Arial', 11),
            bg='#f5f5f5'
        ).pack(side=tk.LEFT, padx=(0, 20))

        tk.Radiobutton(
            operation_frame,
            text="Çöz",
            variable=self.operation_var,
            value="decrypt",
            font=('Arial', 11),
            bg='#f5f5f5'
        ).pack(side=tk.LEFT)

        tk.Label(encryption_frame, text="Veri Türü:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.data_type_var = tk.StringVar(value="text")
        data_type_frame = tk.Frame(encryption_frame, bg='#f5f5f5')
        data_type_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Radiobutton(
            data_type_frame,
            text="Metin",
            variable=self.data_type_var,
            value="text",
            font=('Arial', 11),
            bg='#f5f5f5'
        ).pack(side=tk.LEFT, padx=(0, 20))

        tk.Radiobutton(
            data_type_frame,
            text="Dosya",
            variable=self.data_type_var,
            value="file",
            font=('Arial', 11),
            bg='#f5f5f5'
        ).pack(side=tk.LEFT)

    def create_data_panel(self, parent):
        data_frame = tk.LabelFrame(
            parent,
            text="Veri Girişi",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        data_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        file_frame = tk.Frame(data_frame, bg='#f5f5f5')
        file_frame.pack(fill=tk.X, padx=10, pady=10)

        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, font=('Arial', 11), state='readonly')
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        tk.Button(
            file_frame,
            text="Dosya Seç",
            command=self.select_file,
            font=('Arial', 10),
            bg='#2196F3',
            fg='white',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.RIGHT)

        tk.Label(data_frame, text="Metin:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.text_input = scrolledtext.ScrolledText(
            data_frame,
            font=('Consolas', 11),
            height=15,
            wrap=tk.WORD
        )
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        button_frame = tk.Frame(data_frame, bg='#f5f5f5')
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(
            button_frame,
            text="İşlemi Başlat",
            command=self.start_operation,
            font=('Arial', 12, 'bold'),
            bg='#FF9800',
            fg='white',
            relief=tk.FLAT,
            padx=20,
            pady=10
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            button_frame,
            text="Temizle",
            command=self.clear_input,
            font=('Arial', 11),
            bg='#f44336',
            fg='white',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.RIGHT)

    def create_file_management_panel(self, parent):
        file_frame = tk.LabelFrame(
            parent,
            text="Dosya Yönetimi",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        file_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(0, 10))

        tk.Label(file_frame, text="Server'daki Dosyalar:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        list_frame = tk.Frame(file_frame, bg='#f5f5f5')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.file_listbox = tk.Listbox(
            list_frame,
            font=('Consolas', 10),
            bg='white',
            selectbackground='#2196F3',
            selectforeground='white',
            height=8
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        file_button_frame = tk.Frame(file_frame, bg='#f5f5f5')
        file_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(
            file_button_frame,
            text="Yenile",
            command=self.refresh_file_list,
            font=('Arial', 10),
            bg='#4CAF50',
            fg='white',
            relief=tk.FLAT,
            padx=10
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            file_button_frame,
            text="İndir",
            command=self.download_selected_file,
            font=('Arial', 10),
            bg='#2196F3',
            fg='white',
            relief=tk.FLAT,
            padx=10
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            file_button_frame,
            text="Sil",
            command=self.delete_selected_file,
            font=('Arial', 10),
            bg='#f44336',
            fg='white',
            relief=tk.FLAT,
            padx=10
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            file_button_frame,
            text="Bilgi",
            command=self.show_file_info,
            font=('Arial', 10),
            bg='#FF9800',
            fg='white',
            relief=tk.FLAT,
            padx=10
        ).pack(side=tk.RIGHT)

        tk.Label(file_frame, text="Seçili Dosya Bilgisi:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.file_info_text = tk.Text(
            file_frame,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg='#333333',
            height=4,
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.file_info_text.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_selected)

        self.server_files = []

    def create_results_panel(self, parent):

        results_frame = tk.LabelFrame(
            parent,
            text="Sonuçlar ve Loglar",
            font=('Arial', 12, 'bold'),
            bg='#f5f5f5',
            fg='#333333'
        )
        results_frame.pack(fill=tk.X, pady=(10, 0))

        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=('Consolas', 11),
            bg='#2c3e50',
            fg='#ecf0f1',
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_button_frame = tk.Frame(results_frame, bg='#f5f5f5')
        result_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(
            result_button_frame,
            text="Sonucu Kaydet",
            command=self.save_result,
            font=('Arial', 10),
            bg='#4CAF50',
            fg='white',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)

        tk.Button(
            result_button_frame,
            text="Temizle",
            command=self.clear_results,
            font=('Arial', 10),
            bg='#f44336',
            fg='white',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.RIGHT)

    def create_caesar_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()

        tk.Label(self.params_frame, text="Shift Değeri:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W)

        self.shift_var = tk.StringVar(value="3")
        shift_entry = tk.Entry(self.params_frame, textvariable=self.shift_var, width=10, font=('Arial', 11))
        shift_entry.pack(anchor=tk.W, pady=(5, 0))

    def create_vigenere_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()

        tk.Label(self.params_frame, text="Anahtar Kelime:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W)

        self.keyword_var = tk.StringVar(value="KEY")
        keyword_entry = tk.Entry(self.params_frame, textvariable=self.keyword_var, width=20, font=('Arial', 11))
        keyword_entry.pack(anchor=tk.W, pady=(5, 0))

    def create_affine_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()

        tk.Label(self.params_frame, text="A Değeri:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W)
        self.a_var = tk.StringVar(value="5")
        a_entry = tk.Entry(self.params_frame, textvariable=self.a_var, width=10, font=('Arial', 11))
        a_entry.pack(anchor=tk.W, pady=(5, 0))

        tk.Label(self.params_frame, text="B Değeri:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W, pady=(10, 0))
        self.b_var = tk.StringVar(value="8")
        b_entry = tk.Entry(self.params_frame, textvariable=self.b_var, width=10, font=('Arial', 11))
        b_entry.pack(anchor=tk.W, pady=(5, 0))

    def create_substitution_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()

        tk.Label(self.params_frame, text="Yerine Geçme Anahtarı:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W)

        self.substitution_key_var = tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")
        substitution_entry = tk.Entry(self.params_frame, textvariable=self.substitution_key_var, width=30, font=('Arial', 11))
        substitution_entry.pack(anchor=tk.W, pady=(5, 0))

        tk.Button(
            self.params_frame,
            text="Rastgele Anahtar Oluştur",
            command=self.generate_substitution_key,
            font=('Arial', 10),
            bg='#9C27B0',
            fg='white',
            relief=tk.FLAT,
            padx=10
        ).pack(anchor=tk.W, pady=(10, 0))

    def create_rail_fence_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()

        tk.Label(self.params_frame, text="Ray Sayısı:", font=('Arial', 11), bg='#f5f5f5').pack(anchor=tk.W)

        self.rails_var = tk.StringVar(value="3")
        rails_entry = tk.Entry(self.params_frame, textvariable=self.rails_var, width=10, font=('Arial', 11))
        rails_entry.pack(anchor=tk.W, pady=(5, 0))

    def on_algorithm_changed(self, event=None):
        algorithm = self.algorithm_var.get()

        if algorithm == "caesar":
            self.create_caesar_params()
        elif algorithm == "vigenere":
            self.create_vigenere_params()
        elif algorithm == "affine":
            self.create_affine_params()
        elif algorithm == "substitution":
            self.create_substitution_params()
        elif algorithm == "rail_fence":
            self.create_rail_fence_params()

    def connect_to_server(self):

        if not self.client.is_connected:
            host = self.host_var.get()
            port = int(self.port_var.get())

            def retry_callback(attempt, max_attempts, error):
                self.add_log(f"Bağlantı denemesi {attempt}/{max_attempts} başarısız: {error}")

            def connect_thread():
                success = self.client.connect(host, port, retry_callback)

                self.root.after(0, lambda: self.update_connection_status(success))

            threading.Thread(target=connect_thread, daemon=True).start()
        else:
            self.client.disconnect()
            self.update_connection_status(False)

    def update_connection_status(self, connected):

        if connected:
            self.connection_button.config(text="Bağlantıyı Kes", bg='#f44336')
            self.connection_status.config(text="Bağlı", fg='#4CAF50')
            self.add_log(f"Server'a bağlandı: {self.host_var.get()}:{self.port_var.get()}")
            self.refresh_file_list()
        else:
            self.connection_button.config(text="Bağlan", bg='#4CAF50')
            self.connection_status.config(text="Bağlı değil", fg='#f44336')
            self.add_log("Server bağlantısı kesildi")
            self.file_listbox.delete(0, tk.END)
            self.server_files = []

    def select_file(self):

        filename = filedialog.askopenfilename(
            title="Şifrelenecek Dosyayı Seç",
            filetypes=[
                ("Tüm dosyalar", "*.*"),
                ("Metin dosyaları", "*.txt"),
                ("Resim dosyaları", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Ses dosyaları", "*.mp3 *.wav *.ogg"),
                ("Video dosyaları", "*.mp4 *.avi *.mov *.mkv")
            ]
        )

        if filename:
            self.file_path_var.set(filename)
            self.add_log(f"Dosya seçildi: {os.path.basename(filename)}")

    def get_algorithm_params(self):

        algorithm = self.algorithm_var.get()

        if algorithm == "caesar":
            return {"shift": int(self.shift_var.get())}
        elif algorithm == "vigenere":
            return {"keyword": self.keyword_var.get()}
        elif algorithm == "affine":
            return {"a": int(self.a_var.get()), "b": int(self.b_var.get())}
        elif algorithm == "substitution":
            return {"substitution_key": self.substitution_key_var.get()}
        elif algorithm == "rail_fence":
            return {"rails": int(self.rails_var.get())}

        return {}

    def start_operation(self):

        if not self.client.is_connected:
            messagebox.showerror("Hata", "Önce server'a bağlanmalısınız!")
            return

        operation = self.operation_var.get()
        algorithm = self.algorithm_var.get()
        data_type = self.data_type_var.get()

        try:
            params = self.get_algorithm_params()
        except ValueError as e:
            messagebox.showerror("Hata", f"Geçersiz parametre: {str(e)}")
            return

        def operation_thread():
            try:
                if data_type == "text":
                    text = self.text_input.get("1.0", tk.END).strip()
                    if not text:
                        self.root.after(0, lambda: messagebox.showerror("Hata", "Metin girişi boş olamaz!"))
                        return

                    if operation == "encrypt":
                        result = self.client.encrypt_text(text, algorithm, **params)
                    else:
                        result = self.client.decrypt_text(text, algorithm, **params)

                else:
                    file_path = self.file_path_var.get()
                    if not file_path:
                        self.root.after(0, lambda: messagebox.showerror("Hata", "Dosya seçmelisiniz!"))
                        return

                    if operation == "encrypt":
                        result = self.client.encrypt_file(file_path, algorithm, **params)
                    else:
                        if not self.current_encrypted_data:
                            self.root.after(0, lambda: messagebox.showerror("Hata", "Önce bir dosyayı şifreleyin!"))
                            return

                        output_path = filedialog.asksaveasfilename(
                            title="Çözülmüş Dosyayı Kaydet",
                            defaultextension=".*"
                        )
                        if output_path:
                            result = self.client.decrypt_file(self.current_encrypted_data, algorithm, output_path, **params)

                self.root.after(0, lambda: self.show_result(result, operation, data_type))

            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"İşlem hatası: {str(e)}"))

        threading.Thread(target=operation_thread, daemon=True).start()
        self.add_log(f"{operation.capitalize()} işlemi başlatıldı...")

    def show_result(self, result, operation, data_type):
        timestamp = datetime.now().strftime("%H:%M:%S")

        if result['success']:
            if data_type == "text":
                if operation == "encrypt":
                    encrypted_text = result['encrypted_data']
                    self.add_log(f"[{timestamp}] Şifreleme başarılı!")
                    self.add_log(f"Şifrelenmiş metin:\n{encrypted_text}")

                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert("1.0", encrypted_text)

                    if messagebox.askyesno("Kaydet", "Şifrelenmiş metni server'a kaydetmek ister misiniz?"):
                        self.save_encrypted_to_server(encrypted_text, algorithm, params, "text_encrypted.txt")

                else:
                    decrypted_text = result['decrypted_data']
                    self.add_log(f"[{timestamp}] Çözme başarılı!")
                    self.add_log(f"Çözülmüş metin:\n{decrypted_text}")

                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert("1.0", decrypted_text)

            else:
                if operation == "encrypt":
                    self.current_encrypted_data = result['encrypted_data']
                    self.add_log(f"[{timestamp}] Dosya şifreleme başarılı!")
                    self.add_log(f"Şifrelenmiş veri boyutu: {len(result['encrypted_data'])} karakter")

                    if messagebox.askyesno("Kaydet", "Şifrelenmiş dosyayı server'a kaydetmek ister misiniz?"):
                        original_filename = os.path.basename(self.file_path_var.get()) if self.file_path_var.get() else "encrypted_file.dat"
                        self.save_encrypted_to_server(result['encrypted_data'], algorithm, params, original_filename)

                else:
                    self.add_log(f"[{timestamp}] Dosya çözme başarılı!")
                    self.add_log(f"Dosya kaydedildi: {result.get('saved_path', 'Bilinmiyor')}")

        else:
            self.add_log(f"[{timestamp}] İşlem başarısız: {result['error']}")

    def add_log(self, message):

        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, log_entry)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)

    def clear_input(self):

        self.text_input.delete("1.0", tk.END)
        self.file_path_var.set("")
        self.current_encrypted_data = None

    def clear_results(self):

        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state=tk.DISABLED)

    def save_result(self):

        content = self.results_text.get("1.0", tk.END)
        if not content.strip():
            messagebox.showwarning("Uyarı", "Kaydedilecek sonuç bulunmuyor!")
            return

        filename = filedialog.asksaveasfilename(
            title="Sonucu Kaydet",
            defaultextension=".txt",
            filetypes=[("Metin dosyaları", "*.txt"), ("Tüm dosyalar", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Başarılı", f"Sonuç kaydedildi: {filename}")
            except Exception as e:
                messagebox.showerror("Hata", f"Kaydetme hatası: {str(e)}")

    def generate_substitution_key(self):

        import random
        import string

        alphabet = list(string.ascii_uppercase)
        random.shuffle(alphabet)
        random_key = ''.join(alphabet)

        self.substitution_key_var.set(random_key)
        self.add_log(f"Rastgele anahtar oluşturuldu: {random_key}")

    def refresh_file_list(self):

        if not self.client.is_connected:
            messagebox.showerror("Hata", "Önce server'a bağlanmalısınız!")
            return

        def refresh_thread():
            try:
                result = self.client.list_files()
                self.root.after(0, lambda: self.update_file_list(result))
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"Dosya listesi alınamadı: {str(e)}"))

        threading.Thread(target=refresh_thread, daemon=True).start()
        self.add_log("Dosya listesi yenileniyor...")

    def update_file_list(self, result):

        if result['success']:
            self.server_files = result['files']
            self.file_listbox.delete(0, tk.END)

            for file_info in self.server_files:
                display_text = f"{file_info['filename']} ({file_info['algorithm']}) - {file_info['created_at'][:19]}"
                self.file_listbox.insert(tk.END, display_text)

            self.add_log(f"Dosya listesi güncellendi: {len(self.server_files)} dosya")
        else:
            self.add_log(f"Dosya listesi alınamadı: {result['error']}")

    def on_file_selected(self, event):

        selection = self.file_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        if index < len(self.server_files):
            file_info = self.server_files[index]
            self.show_file_info_display(file_info)

    def show_file_info_display(self, file_info):

        info_text = f"Dosya: {file_info.get('filename', 'Bilinmiyor')}\nAlgoritma: {file_info.get('algorithm', 'Bilinmiyor')}\nBoyut: {file_info.get('file_size', 0)} bytes\nOluşturulma: {file_info.get('created_at', 'Bilinmiyor')}"

        self.file_info_text.config(state=tk.NORMAL)
        self.file_info_text.delete("1.0", tk.END)
        self.file_info_text.insert("1.0", info_text)
        self.file_info_text.config(state=tk.DISABLED)

    def download_selected_file(self):

        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return

        index = selection[0]
        if index >= len(self.server_files):
            return

        file_info = self.server_files[index]
        file_id = file_info['file_id']

        def download_thread():
            try:
                result = self.client.download_file(file_id)
                self.root.after(0, lambda: self.handle_download_result(result, file_info))
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"Dosya indirilemedi: {str(e)}"))

        threading.Thread(target=download_thread, daemon=True).start()
        self.add_log(f"Dosya indiriliyor: {file_info['filename']}")

    def handle_download_result(self, result, file_info):

        if result['success']:
            filename = filedialog.asksaveasfilename(
                title="Şifrelenmiş Dosyayı Kaydet",
                initialvalue=file_info['filename'],
                defaultextension=".enc"
            )

            if filename:
                try:
                    import base64
                    file_data = base64.b64decode(result['file_data'])
                    with open(filename, 'wb') as f:
                        f.write(file_data)

                    self.add_log(f"Dosya kaydedildi: {filename}")
                    messagebox.showinfo("Başarılı", f"Dosya kaydedildi:\n{filename}")
                except Exception as e:
                    self.add_log(f"Dosya kaydetme hatası: {str(e)}")
                    messagebox.showerror("Hata", f"Dosya kaydedilemedi: {str(e)}")
        else:
            self.add_log(f"Dosya indirilemedi: {result['error']}")
            messagebox.showerror("Hata", f"Dosya indirilemedi: {result['error']}")

    def delete_selected_file(self):

        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return

        index = selection[0]
        if index >= len(self.server_files):
            return

        file_info = self.server_files[index]

        if not messagebox.askyesno("Onay", f"Dosyayı silmek istediğinizden emin misiniz?\n\n{file_info['filename']}"):
            return

        def delete_thread():
            try:
                result = self.client.delete_file(file_info['file_id'])
                self.root.after(0, lambda: self.handle_delete_result(result, file_info))
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"Dosya silinemedi: {str(e)}"))

        threading.Thread(target=delete_thread, daemon=True).start()
        self.add_log(f"Dosya siliniyor: {file_info['filename']}")

    def handle_delete_result(self, result, file_info):
        if result['success']:
            self.add_log(f"Dosya silindi: {file_info['filename']}")
            messagebox.showinfo("Başarılı", "Dosya silindi!")
            self.refresh_file_list()
        else:
            self.add_log(f"Dosya silinemedi: {result['error']}")
            messagebox.showerror("Hata", f"Dosya silinemedi: {result['error']}")

    def show_file_info(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return

        index = selection[0]
        if index >= len(self.server_files):
            return

        file_info = self.server_files[index]
        file_id = file_info['file_id']

        def info_thread():
            try:
                result = self.client.get_file_info(file_id)
                self.root.after(0, lambda: self.show_detailed_file_info(result))
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"Dosya bilgisi alınamadı: {str(e)}"))

        threading.Thread(target=info_thread, daemon=True).start()

    def show_detailed_file_info(self, result):
        if result['success']:
            file_info = result['file_info']

            info_window = tk.Toplevel(self.root)
            info_window.title("Dosya Bilgisi")
            info_window.geometry("500x400")
            info_window.resizable(False, False)

            info_window.update_idletasks()
            x = (info_window.winfo_screenwidth() // 2) - (500 // 2)
            y = (info_window.winfo_screenheight() // 2) - (400 // 2)
            info_window.geometry(f"500x400+{x}+{y}")

            info_text = f"Dosya: {file_info.get('filename', 'Bilinmiyor')}\nAlgoritma: {file_info.get('algorithm', 'Bilinmiyor')}\nBoyut: {file_info.get('file_size', 0)} bytes\nOluşturulma: {file_info.get('created_at', 'Bilinmiyor')}\nParametreler: {file_info.get('params', {})}"

            text_widget = scrolledtext.ScrolledText(
                info_window,
                font=('Consolas', 10),
                bg='#f8f9fa',
                fg='#333333',
                wrap=tk.WORD
            )
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert("1.0", info_text)
            text_widget.config(state=tk.DISABLED)

            tk.Button(
                info_window,
                text="Kapat",
                command=info_window.destroy,
                font=('Arial', 11),
                bg='#2196F3',
                fg='white',
                relief=tk.FLAT,
                padx=20,
                pady=5
            ).pack(pady=10)
        else:
            self.add_log(f"Dosya bilgisi alınamadı: {result['error']}")
            messagebox.showerror("Hata", f"Dosya bilgisi alınamadı: {result['error']}")

    def save_encrypted_to_server(self, encrypted_data, algorithm, params, filename):
        def save_thread():
            try:
                import base64
                encoded_data = base64.b64encode(encrypted_data.encode('utf-8') if isinstance(encrypted_data, str) else encrypted_data).decode('utf-8')

                result = self.client.save_encrypted_file(encoded_data, algorithm, params, filename)
                self.root.after(0, lambda: self.handle_save_result(result, filename))
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"Server'a kaydetme hatası: {str(e)}"))

        threading.Thread(target=save_thread, daemon=True).start()
        self.add_log(f"Server'a kaydediliyor: {filename}")

    def handle_save_result(self, result, filename):
        if result['success']:
            self.add_log(f"Dosya server'a kaydedildi: {filename} (ID: {result['file_id']})")
            messagebox.showinfo("Başarılı", f"Dosya server'a kaydedildi!\n\nDosya ID: {result['file_id']}")
            self.refresh_file_list()
        else:
            self.add_log(f"Server'a kaydetme başarısız: {result['error']}")
            messagebox.showerror("Hata", f"Server'a kaydetme başarısız: {result['error']}")

def main():
    root = tk.Tk()
    app = ClientWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
