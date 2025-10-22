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
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False
        self.connected_clients = {}
        self.clients_lock = threading.Lock()  
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        logger = logging.getLogger(f'EncryptionServer_{self.port}')
        logger.setLevel(logging.INFO)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
            self.server_socket.settimeout(1.0)  # Timeout ekle
            
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
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except socket.error:
                    if self.is_running:
                        self.logger.error("Server socket hatasi")
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
                except:
                    pass
            self.connected_clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
                self.logger.info("Server durduruldu")
            except:
                pass
                
    def handle_client(self, client_socket, client_info):
        try:
            while self.is_running:
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                    
                length = int.from_bytes(length_data, byteorder='big')
                
                data = b''
                while len(data) < length:
                    chunk = client_socket.recv(min(length - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk
                    
                if len(data) != length:
                    break
                    
                try:
                    message = json.loads(data.decode('utf-8'))
                    response = self.process_message(message)
                    
                    response_json = json.dumps(response, ensure_ascii=False)
                    response_bytes = response_json.encode('utf-8')
                    
                    length = len(response_bytes)
                    client_socket.send(length.to_bytes(4, byteorder='big'))
                    
                    client_socket.send(response_bytes)
                    
                except json.JSONDecodeError:
                    error_response = {
                        'success': False,
                        'error': 'Geçersiz JSON formatı'
                    }
                    response_json = json.dumps(error_response, ensure_ascii=False)
                    response_bytes = response_json.encode('utf-8')
                    
                    length = len(response_bytes)
                    client_socket.send(length.to_bytes(4, byteorder='big'))
                    client_socket.send(response_bytes)
                    
                except Exception as e:
                    error_response = {
                        'success': False,
                        'error': f'İşlem hatası: {str(e)}'
                    }
                    response_json = json.dumps(error_response, ensure_ascii=False)
                    response_bytes = response_json.encode('utf-8')
                    
                    try:
                        length = len(response_bytes)
                        client_socket.send(length.to_bytes(4, byteorder='big'))
                        client_socket.send(response_bytes)
                    except:
                        pass
                    
        except Exception as e:
            self.logger.error(f"Client isleme hatasi [{client_info}]: {e}")
            
        finally:
            client_socket.close()
            with self.clients_lock:
                if client_info in self.connected_clients:
                    del self.connected_clients[client_info]
            self.logger.info(f"Client baglantisi sonlandirildi: {client_info}")
            
    def process_message(self, message):
        try:
            operation = message.get('operation')
            algorithm = message.get('algorithm')
            data = message.get('data')
            params = message.get('params', {})
            data_type = message.get('data_type', 'text')  # text veya file
            
            self.logger.info(f"Islem: {operation}, Algoritma: {algorithm}, Tip: {data_type}")
            
            if operation == 'encrypt':
                if data_type == 'file':
                    try:
                        file_data = base64.b64decode(data)
                        result = encryption_service.encrypt_file(file_data, algorithm, **params)
                    except Exception as e:
                        result = {
                            'success': False,
                            'error': f'Dosya şifreleme hatası: {str(e)}'
                        }
                else:
                    result = encryption_service.encrypt_text(data, algorithm, **params)
                    
            elif operation == 'decrypt':
                if data_type == 'file':
                    try:
                        file_data = base64.b64decode(data)
                        result = encryption_service.decrypt_file(file_data, algorithm, **params)
                    except Exception as e:
                        result = {
                            'success': False,
                            'error': f'Dosya çözme hatası: {str(e)}'
                        }
                else:
                    result = encryption_service.decrypt_text(data, algorithm, **params)
                    
            elif operation == 'list_algorithms':
                algorithms = encryption_service.get_available_algorithms()
                result = {
                    'success': True,
                    'algorithms': algorithms
                }
                
            elif operation == 'algorithm_info':
                try:
                    info = encryption_service.get_algorithm_info(algorithm)
                    result = {
                        'success': True,
                        'algorithm_info': info
                    }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Algoritma bilgisi alınamadı: {str(e)}'
                    }
                    
            elif operation == 'list_files':
                try:
                    files = file_manager.list_files()
                    result = {
                        'success': True,
                        'files': files
                    }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Dosya listesi alınamadı: {str(e)}'
                    }
                    
            elif operation == 'get_file_info':
                try:
                    file_id = message.get('file_id')
                    if not file_id:
                        result = {
                            'success': False,
                            'error': 'Dosya ID belirtilmelidir'
                        }
                    else:
                        file_info = file_manager.get_file_info(file_id)
                        if file_info:
                            result = {
                                'success': True,
                                'file_info': file_info
                            }
                        else:
                            result = {
                                'success': False,
                                'error': 'Dosya bulunamadı'
                            }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Dosya bilgisi alınamadı: {str(e)}'
                    }
                    
            elif operation == 'download_file':
                try:
                    file_id = message.get('file_id')
                    if not file_id:
                        result = {
                            'success': False,
                            'error': 'Dosya ID belirtilmelidir'
                        }
                    else:
                        file_data = file_manager.get_encrypted_file(file_id)
                        if file_data:
                            import base64
                            encoded_data = base64.b64encode(file_data).decode('utf-8')
                            result = {
                                'success': True,
                                'file_data': encoded_data,
                                'file_id': file_id
                            }
                        else:
                            result = {
                                'success': False,
                                'error': 'Dosya bulunamadı'
                            }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Dosya indirilemedi: {str(e)}'
                    }
                    
            elif operation == 'delete_file':
                try:
                    file_id = message.get('file_id')
                    if not file_id:
                        result = {
                            'success': False,
                            'error': 'Dosya ID belirtilmelidir'
                        }
                    else:
                        success = file_manager.delete_file(file_id)
                        result = {
                            'success': success,
                            'message': 'Dosya silindi' if success else 'Dosya silinemedi'
                        }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Dosya silinemedi: {str(e)}'
                    }
                    
            elif operation == 'save_encrypted_file':
                try:
                    encrypted_data = message.get('encrypted_data')
                    algorithm = message.get('algorithm')
                    params = message.get('params', {})
                    original_filename = message.get('original_filename')
                    
                    if not encrypted_data or not algorithm:
                        result = {
                            'success': False,
                            'error': 'Şifrelenmiş veri ve algoritma belirtilmelidir'
                        }
                    else:
                        import base64
                        file_data = base64.b64decode(encrypted_data)
                        
                        file_id = file_manager.save_encrypted_file(
                            file_data, algorithm, params, original_filename
                        )
                        
                        result = {
                            'success': True,
                            'file_id': file_id,
                            'message': 'Dosya kaydedildi'
                        }
                except Exception as e:
                    result = {
                        'success': False,
                        'error': f'Dosya kaydedilemedi: {str(e)}'
                    }
                    
            else:
                result = {
                    'success': False,
                    'error': f'Geçersiz işlem: {operation}'
                }
                
            self.logger.info(f"Islem tamamlandi: {'Basarili' if result['success'] else 'Basarisiz'}")
            return result
            
        except Exception as e:
            self.logger.error(f"Mesaj isleme hatasi: {e}")
            return {
                'success': False,
                'error': str(e)
            }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Kriptoloji Şifreleme Server')
    parser.add_argument('--host', default='0.0.0.0', help='Server host adresi')
    parser.add_argument('--port', type=int, default=8080, help='Server port numarası')
    
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