import socket
import json
import sys
import os
import base64
import time
import threading
from typing import Optional, Callable

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class EncryptionClient:
    def __init__(self):
        self.socket = None
        self.is_connected = False
        self.host = None
        self.port = None
        self.connection_lock = threading.Lock()
        self.max_retries = 3
        self.retry_delay = 1.0

    def connect(
        self, host="127.0.0.1", port=8080, retry_callback: Optional[Callable] = None
    ):
        with self.connection_lock:
            for attempt in range(self.max_retries):
                try:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(10.0)
                    self.socket.connect((host, port))
                    self.host = host
                    self.port = port
                    self.is_connected = True
                    print(f"Server'a bağlandı: {host}:{port}")
                    return True
                except Exception as e:
                    print(
                        f"Bağlantı denemesi {attempt + 1}/{self.max_retries} başarısız: {e}"
                    )
                    if self.socket:
                        try:
                            self.socket.close()
                        except:
                            pass
                        self.socket = None
                    if attempt < self.max_retries - 1:
                        if retry_callback:
                            retry_callback(attempt + 1, self.max_retries, str(e))
                        time.sleep(self.retry_delay)
                    else:
                        self.is_connected = False
                        return False

    def disconnect(self):
        with self.connection_lock:
            try:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                self.is_connected = False
                print("Bağlantı kesildi")
            except:
                pass

    def send_message(self, message):
        if not self.is_connected:
            return {"success": False, "error": "Server'a bağlı değilsiniz"}
        try:
            message_bytes = json.dumps(message, ensure_ascii=False).encode("utf-8")
            self.socket.send(len(message_bytes).to_bytes(4, byteorder="big"))
            self.socket.sendall(message_bytes)
            length_data = self.socket.recv(4)
            if not length_data:
                return {"success": False, "error": "Server bağlantısı kesildi"}
            length = int.from_bytes(length_data, byteorder="big")
            response_data = b""
            while len(response_data) < length:
                chunk = self.socket.recv(min(length - len(response_data), 4096))
                if not chunk:
                    return {"success": False, "error": "Server bağlantısı kesildi"}
                response_data += chunk
            return json.loads(response_data.decode("utf-8"))
        except Exception as e:
            return {"success": False, "error": f"Mesaj gönderme hatası: {e}"}

    def encrypt_text(self, text, algorithm, **params):
        return self.send_message(
            {
                "operation": "encrypt",
                "algorithm": algorithm,
                "data": text,
                "data_type": "text",
                "params": params,
            }
        )

    def decrypt_text(self, encrypted_text, algorithm, **params):
        return self.send_message(
            {
                "operation": "decrypt",
                "algorithm": algorithm,
                "data": encrypted_text,
                "data_type": "text",
                "params": params,
            }
        )

    def encrypt_file(self, file_path, algorithm, **params):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            encoded_data = base64.b64encode(file_data).decode("utf-8")
            message = {
                "operation": "encrypt",
                "algorithm": algorithm,
                "data": encoded_data,
                "data_type": "file",
                "params": params,
                "filename": os.path.basename(file_path),
            }
            return self.send_message(message)
        except Exception as e:
            return {"success": False, "error": f"Dosya okuma hatası: {e}"}

    def decrypt_file(self, encrypted_data, algorithm, output_path, **params):
        message = {
            "operation": "decrypt",
            "algorithm": algorithm,
            "data": encrypted_data,
            "data_type": "file",
            "params": params,
        }
        result = self.send_message(message)
        if result.get("success"):
            try:
                file_data = base64.b64decode(result["file_data"])
                with open(output_path, "wb") as f:
                    f.write(file_data)
                result["saved_path"] = output_path
                return result
            except Exception as e:
                return {"success": False, "error": f"Dosya kaydetme hatası: {e}"}
        return result

    def list_algorithms(self):
        return self.send_message({"operation": "list_algorithms"})

    def get_algorithm_info(self, algorithm):
        return self.send_message(
            {"operation": "algorithm_info", "algorithm": algorithm}
        )

    def list_files(self):
        return self.send_message({"operation": "list_files"})

    def get_file_info(self, file_id):
        return self.send_message({"operation": "get_file_info", "file_id": file_id})

    def download_file(self, file_id):
        return self.send_message({"operation": "download_file", "file_id": file_id})

    def delete_file(self, file_id):
        return self.send_message({"operation": "delete_file", "file_id": file_id})

    def save_encrypted_file(
        self, encrypted_data, algorithm, params, original_filename=None
    ):
        message = {
            "operation": "save_encrypted_file",
            "encrypted_data": encrypted_data,
            "algorithm": algorithm,
            "params": params,
            "original_filename": original_filename,
        }
        return self.send_message(message)

    def send_message_async(self, message, callback: Optional[Callable] = None):
        def _send():
            result = self.send_message(message)
            if callback:
                callback(result)

        thread = threading.Thread(target=_send, daemon=True)
        thread.start()
        return thread


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Kriptoloji Şifreleme Client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--text", default="Merhaba Dünya!")
    parser.add_argument("--algorithm", default="caesar")
    parser.add_argument("--shift", type=int, default=3)
    args = parser.parse_args()
    client = EncryptionClient()
    if not client.connect(args.host, args.port):
        return
    encrypt_result = client.encrypt_text(args.text, args.algorithm, shift=args.shift)
    if encrypt_result.get("success"):
        print(f"Şifrelenmiş metin: {encrypt_result['encrypted_data']}")
        decrypt_result = client.decrypt_text(
            encrypt_result["encrypted_data"], args.algorithm, shift=args.shift
        )
        if decrypt_result.get("success"):
            print(f"Çözülmüş metin: {decrypt_result['decrypted_data']}")
        else:
            print(f"Çözme hatası: {decrypt_result.get('error')}")
    else:
        print(f"Şifreleme hatası: {encrypt_result.get('error')}")
    client.disconnect()


if __name__ == "__main__":
    main()
