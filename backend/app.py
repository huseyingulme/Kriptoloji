import socket
import threading
import json
import sys
import os
import base64
import logging
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.encryption_service import encryption_service
from utils.file_manager import file_manager


class EncryptionServer:
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False
        self.connected_clients = {}
        self.clients_lock = threading.Lock()
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger(f"EncryptionServer_{self.port}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        return logger

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            self.is_running = True
            self.logger.info(f"Sifreleme Server'i baslatildi - {self.host}:{self.port}")

            while self.is_running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_info = f"{address[0]}:{address[1]}"

                    with self.clients_lock:
                        self.connected_clients[client_info] = client_socket

                    self.logger.info(f"Yeni client baglandi: {client_info}")

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_info),
                        daemon=True,
                    )
                    client_thread.start()

                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.is_running:
                        self.logger.error(f"Server socket hatasi: {e}")
                    break

        except Exception as e:
            self.logger.error(f"Server baslatma hatasi: {e}")

    def stop(self):
        self.is_running = False
        with self.clients_lock:
            clients_copy = dict(self.connected_clients)
            for client_info, client_socket in clients_copy.items():
                try:
                    client_socket.close()
                    self.logger.info(f"Client baglantisi kapatildi: {client_info}")
                except Exception:
                    pass
            self.connected_clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
                self.logger.info("Server durduruldu")
            except Exception:
                pass

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
            except socket.timeout:
                continue
            except socket.error:
                return b""
            if not chunk:
                return b""
            data += chunk
        return data

    def handle_client(self, client_socket, client_info):
        client_socket.settimeout(1.0)
        try:
            while self.is_running:
                length_data = self._recv_exact(client_socket, 4)
                if not length_data:
                    break

                length = int.from_bytes(length_data, byteorder="big")
                if length <= 0:
                    break

                data = self._recv_exact(client_socket, length)
                if not data or len(data) != length:
                    break

                try:
                    message = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    error_response = {
                        "success": False,
                        "error": "Geçersiz JSON formatı",
                    }
                    self._send_json(client_socket, error_response)
                    continue

                response = self.process_message(message)

                # ensure response is a dict with 'success' key
                if isinstance(response, (bytes, str)):
                    response = {"success": True, "result": response}
                elif not isinstance(response, dict):
                    response = {"success": True, "result": response}

                try:
                    self._send_json(client_socket, response)
                except Exception as e:
                    self.logger.error(f"Response gönderilemedi [{client_info}]: {e}")
                    break

        except Exception as e:
            self.logger.error(f"Client isleme hatasi [{client_info}]: {e}")

        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            with self.clients_lock:
                if client_info in self.connected_clients:
                    del self.connected_clients[client_info]
            self.logger.info(f"Client baglantisi sonlandirildi: {client_info}")

    def _send_json(self, sock: socket.socket, obj: dict):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        length = len(payload)
        try:
            sock.sendall(length.to_bytes(4, byteorder="big"))
            sock.sendall(payload)
        except socket.error as e:
            raise

    def _normalize_service_result(self, res):
        if isinstance(res, dict):
            # assume service already returned proper dict
            return res
        if isinstance(res, bytes):
            return {"success": True, "result": base64.b64encode(res).decode("utf-8")}
        if isinstance(res, str):
            return {"success": True, "result": res}
        # fallback
        return {"success": True, "result": res}

    def process_message(self, message):
        try:
            operation = message.get("operation")
            algorithm = message.get("algorithm")
            data = message.get("data")
            params = message.get("params", {})
            data_type = message.get("data_type", "text")

            self.logger.info(
                f"Islem: {operation}, Algoritma: {algorithm}, Tip: {data_type}"
            )

            result = {"success": False, "error": "Bilinmeyen hata"}

            if operation == "encrypt":
                if data_type == "file":
                    try:
                        file_data = base64.b64decode(data)
                        svc_res = encryption_service.encrypt_file(
                            file_data, algorithm, **params
                        )
                        result = self._normalize_service_result(svc_res)
                    except Exception as e:
                        result = {
                            "success": False,
                            "error": f"Dosya şifreleme hatası: {str(e)}",
                        }
                else:
                    try:
                        svc_res = encryption_service.encrypt_text(
                            data, algorithm, **params
                        )
                        result = self._normalize_service_result(svc_res)
                    except Exception as e:
                        result = {
                            "success": False,
                            "error": f"Metin şifreleme hatası: {str(e)}",
                        }

            elif operation == "decrypt":
                if data_type == "file":
                    try:
                        file_data = base64.b64decode(data)
                        svc_res = encryption_service.decrypt_file(
                            file_data, algorithm, **params
                        )
                        result = self._normalize_service_result(svc_res)
                    except Exception as e:
                        result = {
                            "success": False,
                            "error": f"Dosya çözme hatası: {str(e)}",
                        }
                else:
                    try:
                        svc_res = encryption_service.decrypt_text(
                            data, algorithm, **params
                        )
                        result = self._normalize_service_result(svc_res)
                    except Exception as e:
                        result = {
                            "success": False,
                            "error": f"Metin çözme hatası: {str(e)}",
                        }

            elif operation == "list_algorithms":
                try:
                    algorithms = encryption_service.get_available_algorithms()
                    result = {"success": True, "algorithms": algorithms}
                except Exception as e:
                    result = {"success": False, "error": f"Algoritmalar alınamadı: {e}"}

            elif operation == "algorithm_info":
                try:
                    info = encryption_service.get_algorithm_info(algorithm)
                    result = {"success": True, "algorithm_info": info}
                except Exception as e:
                    result = {
                        "success": False,
                        "error": f"Algoritma bilgisi alınamadı: {e}",
                    }

            elif operation == "list_files":
                try:
                    files = file_manager.list_files()
                    result = {"success": True, "files": files}
                except Exception as e:
                    result = {
                        "success": False,
                        "error": f"Dosya listesi alınamadı: {e}",
                    }

            elif operation == "get_file_info":
                try:
                    file_id = message.get("file_id")
                    if not file_id:
                        result = {"success": False, "error": "Dosya ID belirtilmelidir"}
                    else:
                        file_info = file_manager.get_file_info(file_id)
                        if file_info:
                            result = {"success": True, "file_info": file_info}
                        else:
                            result = {"success": False, "error": "Dosya bulunamadı"}
                except Exception as e:
                    result = {
                        "success": False,
                        "error": f"Dosya bilgisi alınamadı: {e}",
                    }

            elif operation == "download_file":
                try:
                    file_id = message.get("file_id")
                    if not file_id:
                        result = {"success": False, "error": "Dosya ID belirtilmelidir"}
                    else:
                        file_data = file_manager.get_encrypted_file(file_id)
                        if file_data:
                            encoded_data = base64.b64encode(file_data).decode("utf-8")
                            result = {
                                "success": True,
                                "file_data": encoded_data,
                                "file_id": file_id,
                            }
                        else:
                            result = {"success": False, "error": "Dosya bulunamadı"}
                except Exception as e:
                    result = {"success": False, "error": f"Dosya indirilemedi: {e}"}

            elif operation == "delete_file":
                try:
                    file_id = message.get("file_id")
                    if not file_id:
                        result = {"success": False, "error": "Dosya ID belirtilmelidir"}
                    else:
                        success = file_manager.delete_file(file_id)
                        result = {
                            "success": success,
                            "message": (
                                "Dosya silindi" if success else "Dosya silinemedi"
                            ),
                        }
                except Exception as e:
                    result = {"success": False, "error": f"Dosya silinemedi: {e}"}

            elif operation == "save_encrypted_file":
                try:
                    encrypted_data = message.get("encrypted_data")
                    algorithm = message.get("algorithm")
                    params = message.get("params", {})
                    original_filename = message.get("original_filename")

                    if not encrypted_data or not algorithm:
                        result = {
                            "success": False,
                            "error": "Şifrelenmiş veri ve algoritma belirtilmelidir",
                        }
                    else:
                        file_data = base64.b64decode(encrypted_data)
                        file_id = file_manager.save_encrypted_file(
                            file_data, algorithm, params, original_filename
                        )
                        result = {
                            "success": True,
                            "file_id": file_id,
                            "message": "Dosya kaydedildi",
                        }
                except Exception as e:
                    result = {"success": False, "error": f"Dosya kaydedilemedi: {e}"}

            else:
                result = {"success": False, "error": f"Geçersiz işlem: {operation}"}

            self.logger.info(
                f"Islem tamamlandi: {'Basarili' if result.get('success') else 'Basarisiz'}"
            )
            return result

        except Exception as e:
            self.logger.error(f"Mesaj isleme hatasi: {e}")
            return {"success": False, "error": str(e)}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Kriptoloji Şifreleme Server")
    parser.add_argument("--host", default="0.0.0.0", help="Server host adresi")
    parser.add_argument("--port", type=int, default=8080, help="Server port numarası")

    args = parser.parse_args()

    server = EncryptionServer(host=args.host, port=args.port)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer durduruluyor...")
        server.stop()
    except Exception as e:
        print(f"Server hatasi: {e}")
        server.stop()


if __name__ == "__main__":
    main()
