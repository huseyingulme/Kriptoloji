import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import json
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.encryption_service import encryption_service


class ServerWindow:
    def __init__(self, root):
        self.root = root
        self.server_socket = None
        self.connected_clients = {}
        self.server_thread = None
        self.current_ip = self.get_local_ip()

        self.setup_window()
        self.create_widgets()

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def setup_window(self):
        self.root.title("Kriptoloji Server")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        style = ttk.Style()
        style.theme_use("clam")

        self.root.configure(bg="#f5f5f5")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        try:
            if self.server_socket:
                self.stop_server()
        except:
            pass
        self.root.destroy()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, bg="#f5f5f5", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(
            main_frame,
            text="Kriptoloji Server",
            font=("Arial", 18, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        title_label.pack(pady=(0, 20))

        self.create_server_control(main_frame)

        content_frame = tk.Frame(main_frame, bg="#f5f5f5")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        self.create_clients_panel(content_frame)

        self.create_messages_panel(content_frame)

        self.create_file_management_panel(main_frame)

    def create_server_control(self, parent):
        control_frame = tk.LabelFrame(
            parent,
            text="Server Kontrolü",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        control_frame.pack(fill=tk.X, pady=(0, 10))

        control_inner = tk.Frame(control_frame, bg="#f5f5f5")
        control_inner.pack(fill=tk.X, padx=15, pady=15)

        ip_label = tk.Label(
            control_inner,
            text=f"Server IP: {self.current_ip}",
            font=("Arial", 11, "bold"),
            bg="#f5f5f5",
            fg="#2196F3",
        )
        ip_label.pack(side=tk.LEFT, padx=(0, 30))

        tk.Label(control_inner, text="Port:", font=("Arial", 11), bg="#f5f5f5").pack(
            side=tk.LEFT
        )

        self.port_var = tk.StringVar(value="8080")
        port_entry = tk.Entry(
            control_inner, textvariable=self.port_var, width=8, font=("Arial", 11)
        )
        port_entry.pack(side=tk.LEFT, padx=(5, 15))

        self.server_button = tk.Button(
            control_inner,
            text="Server Başlat",
            command=self.start_server,
            font=("Arial", 11, "bold"),
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=8,
        )
        self.server_button.pack(side=tk.LEFT, padx=(0, 15))

        self.server_status = tk.Label(
            control_inner,
            text="Durduruldu",
            font=("Arial", 11, "bold"),
            bg="#f5f5f5",
            fg="#f44336",
        )
        self.server_status.pack(side=tk.LEFT)

    def create_clients_panel(self, parent):
        clients_frame = tk.LabelFrame(
            parent,
            text="Bağlı Client'lar",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        clients_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.clients_listbox = tk.Listbox(
            clients_frame,
            font=("Consolas", 10),
            bg="white",
            selectbackground="#2196F3",
            selectforeground="white",
        )
        self.clients_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.client_count_label = tk.Label(
            clients_frame,
            text="Bağlı client sayısı: 0",
            font=("Arial", 10),
            bg="#f5f5f5",
            fg="#666666",
        )
        self.client_count_label.pack(pady=(0, 10))

    def create_messages_panel(self, parent):
        messages_frame = tk.LabelFrame(
            parent,
            text="Gelen Mesajlar",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        messages_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.messages_text = scrolledtext.ScrolledText(
            messages_frame,
            font=("Consolas", 10),
            bg="#2c3e50",
            fg="#ecf0f1",
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        msg_button_frame = tk.Frame(messages_frame, bg="#f5f5f5")
        msg_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(
            msg_button_frame,
            text="Temizle",
            command=self.clear_messages,
            font=("Arial", 10),
            bg="#f44336",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.LEFT)

        tk.Button(
            msg_button_frame,
            text="Kaydet",
            command=self.save_logs,
            font=("Arial", 10),
            bg="#2196F3",
            fg="white",
            relief=tk.FLAT,
            padx=15,
        ).pack(side=tk.RIGHT)

    def start_server(self):
        try:
            port = int(self.port_var.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("", port))
            self.server_socket.listen(5)

            self.server_button.config(
                text="Server Durdur", bg="#f44336", command=self.stop_server
            )
            self.server_status.config(text=f"Çalışıyor (Port: {port})", fg="#4CAF50")

            self.server_thread = threading.Thread(
                target=self.accept_clients, daemon=True
            )
            self.server_thread.start()

            self.add_message(f"Server başlatıldı - Port: {port}")

        except Exception as e:
            messagebox.showerror("Hata", f"Server başlatılamadı: {str(e)}")

    def stop_server(self):
        try:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None

            for client_info, client_socket in self.connected_clients.items():
                try:
                    client_socket.close()
                except:
                    pass
            self.connected_clients.clear()

            self.server_button.config(
                text="Server Başlat", bg="#4CAF50", command=self.start_server
            )
            self.server_status.config(text="Durduruldu", fg="#f44336")

            self.clients_listbox.delete(0, tk.END)
            self.client_count_label.config(text="Bağlı client sayısı: 0")
            self.add_message("Server durduruldu")

        except Exception as e:
            messagebox.showerror("Hata", f"Server durdurulamadı: {str(e)}")

    def accept_clients(self):
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_info = f"{address[0]}:{address[1]}"

                self.connected_clients[client_info] = client_socket

                self.root.after(
                    0, lambda info=client_info: self.add_client_to_list(info)
                )
                self.root.after(0, self.update_client_count)
                self.root.after(
                    0,
                    lambda info=client_info: self.add_message(
                        f"Client bağlandı: {info}"
                    ),
                )

                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_info),
                    daemon=True,
                ).start()

            except Exception as e:
                break

    def handle_client(self, client_socket, client_info):
        try:
            while True:
                length_data = client_socket.recv(4)
                if not length_data:
                    break

                length = int.from_bytes(length_data, byteorder="big")

                data = b""
                while len(data) < length:
                    chunk = client_socket.recv(min(length - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk

                if len(data) != length:
                    break

                try:
                    message = json.loads(data.decode("utf-8"))
                    self.root.after(
                        0,
                        lambda msg=message, info=client_info, sock=client_socket: self.process_client_message(
                            msg, info, sock
                        ),
                    )
                except json.JSONDecodeError:
                    self.root.after(
                        0,
                        lambda info=client_info: self.add_message(
                            f"[{info}] Geçersiz veri"
                        ),
                    )

        except Exception as e:
            self.root.after(
                0,
                lambda info=client_info: self.add_message(
                    f"[{info}] Bağlantı kesildi: {str(e)}"
                ),
            )
        finally:
            client_socket.close()
            if client_info in self.connected_clients:
                del self.connected_clients[client_info]
            self.root.after(0, lambda info=client_info: self.remove_client(info))

    def process_client_message(self, message, client_info, client_socket):
        try:
            operation = message.get("operation")
            algorithm = message.get("algorithm")
            data = message.get("data")
            params = message.get("params", {})

            if not data:
                result = {"success": False, "error": "Veri boş olamaz"}
            elif not algorithm:
                result = {"success": False, "error": "Algoritma belirtilmelidir"}
            else:
                self.add_message(
                    f"[{client_info}] {operation} isteği - Algoritma: {algorithm}"
                )

                if operation == "encrypt":
                    result = encryption_service.encrypt_text(data, algorithm, **params)
                elif operation == "decrypt":
                    result = encryption_service.decrypt_text(data, algorithm, **params)
                else:
                    result = {"success": False, "error": f"Geçersiz işlem: {operation}"}

                status = "Başarılı" if result["success"] else "Başarısız"
                self.add_message(f"[{client_info}] İşlem {status}")

            response = json.dumps(result, ensure_ascii=False)
            response_bytes = response.encode("utf-8")

            length = len(response_bytes)
            client_socket.send(length.to_bytes(4, byteorder="big"))

            client_socket.send(response_bytes)

        except Exception as e:
            error_result = {"success": False, "error": f"Server hatası: {str(e)}"}
            response = json.dumps(error_result, ensure_ascii=False)
            response_bytes = response.encode("utf-8")

            try:
                length = len(response_bytes)
                client_socket.send(length.to_bytes(4, byteorder="big"))
                client_socket.send(response_bytes)
            except:
                pass

            self.add_message(f"[{client_info}] İşlem hatası: {str(e)}")

    def add_client_to_list(self, client_info):
        self.clients_listbox.insert(tk.END, client_info)

    def remove_client(self, client_info):
        items = self.clients_listbox.get(0, tk.END)
        for i, item in enumerate(items):
            if item == client_info:
                self.clients_listbox.delete(i)
                break

        self.update_client_count()
        self.add_message(f"Client ayrıldı: {client_info}")

    def update_client_count(self):
        count = len(self.connected_clients)
        self.client_count_label.config(text=f"Bağlı client sayısı: {count}")

    def add_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.insert(tk.END, log_entry)
        self.messages_text.see(tk.END)
        self.messages_text.config(state=tk.DISABLED)

    def clear_messages(self):
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.delete("1.0", tk.END)
        self.messages_text.config(state=tk.DISABLED)

    def save_logs(self):
        from tkinter import filedialog

        filename = filedialog.asksaveasfilename(
            title="Logları Kaydet",
            defaultextension=".txt",
            filetypes=[("Metin dosyaları", "*.txt"), ("Tüm dosyalar", "*.*")],
        )

        if filename:
            try:
                content = self.messages_text.get("1.0", tk.END)
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Başarılı", f"Loglar kaydedildi: {filename}")
            except Exception as e:
                messagebox.showerror("Hata", f"Loglar kaydedilemedi: {str(e)}")

    def create_file_management_panel(self, parent):
        file_frame = tk.LabelFrame(
            parent,
            text="Server Dosya Yönetimi",
            font=("Arial", 12, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        file_frame.pack(fill=tk.X, pady=(10, 0))

        tk.Label(
            file_frame, text="Kayıtlı Dosyalar:", font=("Arial", 11), bg="#f5f5f5"
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        list_frame = tk.Frame(file_frame, bg="#f5f5f5")
        list_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.server_file_listbox = tk.Listbox(
            list_frame,
            font=("Consolas", 10),
            bg="white",
            selectbackground="#2196F3",
            selectforeground="white",
            height=4,
        )
        self.server_file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.server_file_listbox.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.server_file_listbox.config(yscrollcommand=scrollbar.set)

        file_button_frame = tk.Frame(file_frame, bg="#f5f5f5")
        file_button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(
            file_button_frame,
            text="Yenile",
            command=self.refresh_server_files,
            font=("Arial", 10),
            bg="#4CAF50",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            file_button_frame,
            text="Temizle",
            command=self.cleanup_orphaned_files,
            font=("Arial", 10),
            bg="#FF9800",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            file_button_frame,
            text="Depolama Bilgisi",
            command=self.show_storage_info,
            font=("Arial", 10),
            bg="#9C27B0",
            fg="white",
            relief=tk.FLAT,
            padx=10,
        ).pack(side=tk.RIGHT)

        self.server_files = []
        self.refresh_server_files()

    def refresh_server_files(self):
        try:
            from utils.file_manager import file_manager

            files = file_manager.list_files()
            self.server_files = files
            self.server_file_listbox.delete(0, tk.END)

            for file_info in files:
                display_text = f"{file_info['filename']} ({file_info['algorithm']}) - {file_info['created_at'][:19]}"
                self.server_file_listbox.insert(tk.END, display_text)

            self.add_message(f"Server dosya listesi güncellendi: {len(files)} dosya")
        except Exception as e:
            self.add_message(f"Dosya listesi alınamadı: {str(e)}")

    def cleanup_orphaned_files(self):
        try:
            from utils.file_manager import file_manager

            cleaned_count = file_manager.cleanup_orphaned_files()
            self.add_message(f"Temizlenen dosya sayısı: {cleaned_count}")
            messagebox.showinfo(
                "Temizlik", f"{cleaned_count} orphaned dosya temizlendi."
            )
            self.refresh_server_files()
        except Exception as e:
            self.add_message(f"Temizlik hatası: {str(e)}")
            messagebox.showerror("Hata", f"Temizlik hatası: {str(e)}")

    def show_storage_info(self):
        try:
            from utils.file_manager import file_manager

            info = file_manager.get_storage_info()

            info_window = tk.Toplevel(self.root)
            info_window.title("Depolama Bilgileri")
            info_window.geometry("400x300")
            info_window.resizable(False, False)

            info_window.update_idletasks()
            x = (info_window.winfo_screenwidth() // 2) - (400 // 2)
            y = (info_window.winfo_screenheight() // 2) - (300 // 2)
            info_window.geometry(f"400x300+{x}+{y}")

            info_text = f"""Depolama Bilgileri
{'='*40}

Toplam Dosya Sayısı: {info['total_files']}
Toplam Boyut: {info['total_size_mb']} MB ({info['total_size_bytes']} bytes)

Klasörler:
• Şifrelenmiş Dosyalar: {info['encrypted_dir']}
• Metadata: {info['metadata_dir']}"""

            text_widget = tk.Text(
                info_window,
                font=("Consolas", 10),
                bg="#f8f9fa",
                fg="#333333",
                wrap=tk.WORD,
            )
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert("1.0", info_text)
            text_widget.config(state=tk.DISABLED)

            tk.Button(
                info_window,
                text="Kapat",
                command=info_window.destroy,
                font=("Arial", 11),
                bg="#2196F3",
                fg="white",
                relief=tk.FLAT,
                padx=20,
                pady=5,
            ).pack(pady=10)

        except Exception as e:
            self.add_message(f"Depolama bilgisi alınamadı: {str(e)}")
            messagebox.showerror("Hata", f"Depolama bilgisi alınamadı: {str(e)}")


def main():
    root = tk.Tk()
    app = ServerWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
