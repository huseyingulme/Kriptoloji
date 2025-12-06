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
        
    def connect(self, host='127.0.0.1', port=8080, retry_callback: Optional[Callable] = None):
        with self.connection_lock:
            for attempt in range(self.max_retries):
                try:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(10.0)
                    self.socket.connect((host, port))
                    
                    self.host = host
                    self.port = port
                    self.is_connected = True
                    
                    print(f"Server'a baglandi: {host}:{port}")
                    return True
                    
                except Exception as e:
                    print(f"Baglanti denemesi {attempt + 1}/{self.max_retries} basarisiz: {e}")
                    
                    if self.socket:
                        try:
                            self.socket.close()
                        except:
                            pass
                        self.socket = None
                    
                    if attempt < self.max_retries - 1:
                        if retry_callback:
                            retry_callback(attempt + 1, self.max_retries, str(e))
                        print(f"{self.retry_delay} saniye sonra tekrar deneniyor...")
                        time.sleep(self.retry_delay)
                    else:
                        print(f"Tum baglanti denemeleri basarisiz oldu")
                        self.is_connected = False
                        return False
            
    def disconnect(self):
        with self.connection_lock:
            try:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                    
                self.is_connected = False
                print("Baglanti kesildi")
                
            except Exception as e:
                print(f"Baglanti kesme hatasi: {e}")
                
    def send_message(self, message):
        if not self.is_connected:
            return {
                'success': False,
                'error': 'Server\'a bağlı değilsiniz'
            }
        
        try:
            message_json = json.dumps(message, ensure_ascii=False)
            message_bytes = message_json.encode('utf-8')
            
            length = len(message_bytes)
            self.socket.send(length.to_bytes(4, byteorder='big'))
            
            self.socket.send(message_bytes)
            
            length_data = self.socket.recv(4)
            if not length_data:
                return {
                    'success': False,
                    'error': 'Server bağlantısı kesildi'
                }
            
            length = int.from_bytes(length_data, byteorder='big')
            response_data = b''
            while len(response_data) < length:
                chunk = self.socket.recv(min(length - len(response_data), 4096))
                if not chunk:
                    return {
                        'success': False,
                        'error': 'Server bağlantısı kesildi'
                    }
                response_data += chunk
            
            response = json.loads(response_data.decode('utf-8'))
            return response
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Mesaj gönderme hatası: {str(e)}'
            }
            
    def encrypt_text(self, text, algorithm, **params):
        message = {
            'operation': 'encrypt',
            'algorithm': algorithm,
            'data': text,
            'data_type': 'text',
            'params': params
        }
        
        return self.send_message(message)
        
    def decrypt_text(self, encrypted_text, algorithm, **params):
        message = {
            'operation': 'decrypt',
            'algorithm': algorithm,
            'data': encrypted_text,
            'data_type': 'text',
            'params': params
        }
        
        return self.send_message(message)
    
    def encrypt_file(self, file_path, algorithm, **params):
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            message = {
                'operation': 'encrypt',
                'algorithm': algorithm,
                'data': encoded_data,
                'data_type': 'file',
                'params': params,
                'filename': os.path.basename(file_path)
            }
            
            return self.send_message(message)
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Dosya okuma hatası: {str(e)}'
            }
    
    def decrypt_file(self, encrypted_data, algorithm, output_path, **params):
        message = {
            'operation': 'decrypt',
            'algorithm': algorithm,
            'data': encrypted_data,
            'data_type': 'file',
            'params': params
        }
        
        result = self.send_message(message)
        
        if result['success']:
            try:
                file_data = base64.b64decode(result['file_data'])
                with open(output_path, 'wb') as f:
                    f.write(file_data)
                
                result['saved_path'] = output_path
                return result
                
            except Exception as e:
                return {
                    'success': False,
                    'error': f'Dosya kaydetme hatası: {str(e)}'
                }
        
        return result
    
    def list_algorithms(self):
        message = {
            'operation': 'list_algorithms'
        }
        
        return self.send_message(message)
    
    def get_algorithm_info(self, algorithm):
        message = {
            'operation': 'algorithm_info',
            'algorithm': algorithm
        }
        
        return self.send_message(message)
    
    def list_files(self):
        message = {
            'operation': 'list_files'
        }
        
        return self.send_message(message)
    
    def get_file_info(self, file_id):
        message = {
            'operation': 'get_file_info',
            'file_id': file_id
        }
        
        return self.send_message(message)
    
    def download_file(self, file_id):
        message = {
            'operation': 'download_file',
            'file_id': file_id
        }
        
        return self.send_message(message)
    
    def delete_file(self, file_id):
        message = {
            'operation': 'delete_file',
            'file_id': file_id
        }
        
        return self.send_message(message)
    
    def save_encrypted_file(self, encrypted_data, algorithm, params, original_filename=None):
        message = {
            'operation': 'save_encrypted_file',
            'encrypted_data': encrypted_data,
            'algorithm': algorithm,
            'params': params,
            'original_filename': original_filename
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
    
    parser = argparse.ArgumentParser(description='Kriptoloji Şifreleme Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host adresi')
    parser.add_argument('--port', type=int, default=8080, help='Server port numarası')
    parser.add_argument('--text', default='Merhaba Dünya!', help='Şifrelenecek metin')
    parser.add_argument('--algorithm', default='caesar', help='Şifreleme algoritması')
    parser.add_argument('--shift', type=int, default=3, help='Caesar shift değeri')
    
    args = parser.parse_args()
    
    client = EncryptionClient()
    
    try:
        if not client.connect(args.host, args.port):
            return
            
        print(f"Sifreleme: '{args.text}' - Algoritma: {args.algorithm}")
        encrypt_result = client.encrypt_text(args.text, args.algorithm, shift=args.shift)
        
        if encrypt_result['success']:
            print(f"Sifrelenmis metin: {encrypt_result['encrypted_data']}")
            
            print(f"Cozme: '{encrypt_result['encrypted_data']}'")
            decrypt_result = client.decrypt_text(
                encrypt_result['encrypted_data'], 
                args.algorithm, 
                shift=args.shift
            )
            
            if decrypt_result['success']:
                print(f"Cozulmus metin: {decrypt_result['decrypted_data']}")
            else:
                print(f"Cozme hatasi: {decrypt_result['error']}")
        else:
            print(f"Sifreleme hatasi: {encrypt_result['error']}")
            
    except KeyboardInterrupt:
        print("\nClient durduruluyor...")
    except Exception as e:
        print(f"Client hatasi: {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
