import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
from datetime import datetime
import json

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
        style.theme_use("clam")
        self.root.configure(bg="#f5f5f5")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        try:
            if self.client.is_connected:
                self.client.disconnect()
        except:
            pass
        self.root.destroy()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, bg="#f5f5f5", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        title_label = tk.Label(
            main_frame,
            text="Kriptoloji Client",
            font=("Arial", 18, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        title_label.pack(pady=(0, 20))
        self.create_connection_panel(main_frame)
        content_frame = tk.Frame(main_frame, bg="#f5f5f5")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        self.create_encryption_panel(content_frame)
        self.create_data_panel(content_frame)
        self.create_file_management_panel(content_frame)
        self.create_results_panel(main_frame)

    def create_connection_panel(self, parent):
        connection_frame = tk.LabelFrame(
            parent,
            text="Server Bağlantısı",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        connection_frame.pack(fill=tk.X, pady=(0, 10))
        connection_inner = tk.Frame(connection_frame, bg="#f5f5f5")
        connection_inner.pack(fill=tk.X, padx=15, pady=15)
        tk.Label(connection_inner, text="Host:", font=("Arial", 11), bg="#f5f5f5").pack(
            side=tk.LEFT
        )
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(
            connection_inner, textvariable=self.host_var, width=15, font=("Arial", 11)
        ).pack(side=tk.LEFT, padx=(5, 15))
        tk.Label(connection_inner, text="Port:", font=("Arial", 11), bg="#f5f5f5").pack(
            side=tk.LEFT
        )
        self.port_var = tk.StringVar(value="8080")
        tk.Entry(
            connection_inner, textvariable=self.port_var, width=8, font=("Arial", 11)
        ).pack(side=tk.LEFT, padx=(5, 15))
        self.connection_button = tk.Button(
            connection_inner,
            text="Bağlan",
            command=self.connect_to_server,
            font=("Arial", 11, "bold"),
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=8,
        )
        self.connection_button.pack(side=tk.LEFT, padx=(0, 15))
        self.connection_status = tk.Label(
            connection_inner,
            text="Bağlı değil",
            font=("Arial", 11, "bold"),
            bg="#f5f5f5",
            fg="#f44336",
        )
        self.connection_status.pack(side=tk.LEFT)

    def create_encryption_panel(self, parent):
        encryption_frame = tk.LabelFrame(
            parent,
            text="Şifreleme Ayarları",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        encryption_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        tk.Label(
            encryption_frame, text="Algoritma:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        self.algorithm_var = tk.StringVar(value="caesar")
        algorithm_combo = ttk.Combobox(
            encryption_frame,
            textvariable=self.algorithm_var,
            values=["caesar", "vigenere", "affine", "substitution", "rail_fence"],
            state="readonly",
            font=("Arial", 11),
        )
        algorithm_combo.pack(fill=tk.X, padx=10, pady=(0, 10))
        algorithm_combo.bind("<<ComboboxSelected>>", self.on_algorithm_changed)
        self.params_frame = tk.Frame(encryption_frame, bg="#f5f5f5")
        self.params_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.create_caesar_params()
        tk.Label(
            encryption_frame, text="İşlem Türü:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        self.operation_var = tk.StringVar(value="encrypt")
        operation_frame = tk.Frame(encryption_frame, bg="#f5f5f5")
        operation_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Radiobutton(
            operation_frame,
            text="Şifrele",
            variable=self.operation_var,
            value="encrypt",
            font=("Arial", 11),
            bg="#f5f5f5",
        ).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(
            operation_frame,
            text="Çöz",
            variable=self.operation_var,
            value="decrypt",
            font=("Arial", 11),
            bg="#f5f5f5",
        ).pack(side=tk.LEFT)
        tk.Label(
            encryption_frame, text="Veri Türü:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        self.data_type_var = tk.StringVar(value="text")
        data_type_frame = tk.Frame(encryption_frame, bg="#f5f5f5")
        data_type_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Radiobutton(
            data_type_frame,
            text="Metin",
            variable=self.data_type_var,
            value="text",
            font=("Arial", 11),
            bg="#f5f5f5",
        ).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(
            data_type_frame,
            text="Dosya",
            variable=self.data_type_var,
            value="file",
            font=("Arial", 11),
            bg="#f5f5f5",
        ).pack(side=tk.LEFT)

    def create_data_panel(self, parent):
        data_frame = tk.LabelFrame(
            parent,
            text="Veri Girişi",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        data_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        file_frame = tk.Frame(data_frame, bg="#f5f5f5")
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        self.file_path_var = tk.StringVar()
        tk.Entry(
            file_frame,
            textvariable=self.file_path_var,
            font=("Arial", 11),
            state="readonly",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        tk.Button(
            file_frame,
            text="Dosya Seç",
            command=self.select_file,
            font=("Arial", 10),
            bg="#2196F3",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.RIGHT)
        tk.Label(data_frame, text="Metin:", font=("Arial", 11), bg="#f5f5f5").pack(
            anchor=tk.W, padx=10, pady=(10, 5)
        )
        self.text_input = scrolledtext.ScrolledText(
            data_frame, font=("Consolas", 11), height=15, wrap=tk.WORD
        )
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        button_frame = tk.Frame(data_frame, bg="#f5f5f5")
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Button(
            button_frame,
            text="İşlemi Başlat",
            command=self.start_operation,
            font=("Arial", 12, "bold"),
            bg="#FF9800",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=10,
        ).pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(
            button_frame,
            text="Temizle",
            command=self.clear_input,
            font=("Arial", 11),
            bg="#f44336",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.RIGHT)

    def create_file_management_panel(self, parent):
        file_frame = tk.LabelFrame(
            parent,
            text="Dosya Yönetimi",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        file_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(0, 10))
        tk.Label(
            file_frame, text="Server'daki Dosyalar:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        list_frame = tk.Frame(file_frame, bg="#f5f5f5")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.file_listbox = tk.Listbox(
            list_frame,
            font=("Consolas", 10),
            bg="white",
            selectbackground="#2196F3",
            selectforeground="white",
            height=8,
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        file_button_frame = tk.Frame(file_frame, bg="#f5f5f5")
        file_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Button(
            file_button_frame,
            text="Yenile",
            command=self.refresh_file_list,
            font=("Arial", 10),
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(
            file_button_frame,
            text="İndir",
            command=self.download_selected_file,
            font=("Arial", 10),
            bg="#2196F3",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(
            file_button_frame,
            text="Sil",
            command=self.delete_selected_file,
            font=("Arial", 10),
            bg="#f44336",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(
            file_button_frame,
            text="Bilgi",
            command=self.show_file_info,
            font=("Arial", 10),
            bg="#FF9800",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.RIGHT)
        tk.Label(
            file_frame, text="Seçili Dosya Bilgisi:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        self.file_info_text = tk.Text(
            file_frame,
            font=("Consolas", 9),
            bg="#f8f9fa",
            fg="#333333",
            height=4,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.file_info_text.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.file_listbox.bind("<<ListboxSelect>>", self.on_file_selected)
        self.server_files = []

    def create_results_panel(self, parent):
        results_frame = tk.LabelFrame(
            parent,
            text="Sonuçlar ve Loglar",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        results_frame.pack(fill=tk.X, pady=(10, 0))
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 11),
            bg="#2c3e50",
            fg="#ecf0f1",
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        result_button_frame = tk.Frame(results_frame, bg="#f5f5f5")
        result_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Button(
            result_button_frame,
            text="Sonucu Kaydet",
            command=self.save_result,
            font=("Arial", 10),
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.LEFT)
        tk.Button(
            result_button_frame,
            text="Temizle",
            command=self.clear_results,
            font=("Arial", 10),
            bg="#f44336",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.RIGHT)

    def create_caesar_params(self):
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        tk.Label(
            self.params_frame, text="Shift Değeri:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W)
        self.shift_var = tk.StringVar(value="3")
        tk.Entry(
            self.params_frame, textvariable=self.shift_var, width=10, font=("Arial", 11)
        ).pack(anchor=tk.W, pady=(5, 0))

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

    def main_loop(self):
        self.root.mainloop()


def main():
    root = tk.Tk()
    app = ClientWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
