"""
Server - Client İsteklerini Karşılayan ve Şifreleme İşlemlerini Yapan Sınıf

Bu sınıf, server bilgisayarında çalışır ve client'lardan gelen istekleri karşılar.
Tüm şifreleme/deşifreleme işlemleri burada yapılır.

ÖNEMLİ: Tüm şifreleme işlemleri SERVER tarafında yapılır!
Client sadece veri gönderir ve sonucu alır.
"""

import socket
import threading
import time
import base64
from typing import Optional, Dict, Any, Callable
from shared.utils import DataPacket, Logger
from config import config_manager

# Wireshark modunu kontrol et
WIRESHARK_MODE = config_manager.get("features.wireshark_mode", False)


class Server:
    """
    Client isteklerini karşılayan ve şifreleme işlemlerini yöneten server sınıfı.
    
    Görevleri:
    1. Client bağlantılarını kabul etmek
    2. Gelen istekleri işlemek
    3. Şifreleme/deşifreleme işlemlerini ProcessingManager'a yönlendirmek
    4. Sonuçları client'a geri göndermek
    """

    def __init__(self, host: str = None, port: int = None):
        """
        Server'ı başlatır.
        
        Args:
            host: Server IP adresi (varsayılan: config'den alınır)
            port: Server port numarası (varsayılan: config'den alınır)
        """
        self.host = host or config_manager.get("server.host", "localhost")
        self.port = port or config_manager.get("server.port", 12345)
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.clients = {}  # Bağlı clientlar {address: socket}
        self.processing_callback: Optional[Callable] = None  # Şifreleme işlemlerini yapan callback
        self.key_manager = None  # RSA anahtar yönetimi
        self.hybrid_decryption_manager = None  # Hibrit çözme yöneticisi
        self.max_clients = config_manager.get("server.max_clients", 10)
        self.timeout = config_manager.get("server.timeout", 300)
        self.operation_callback: Optional[Callable] = None  # İşlem logları için callback
        self.request_counter = 0

    def start(self):
        """
        Server'ı başlatır ve client bağlantılarını dinlemeye başlar.
        
        İşlem Adımları:
        1. Socket oluşturulur ve ayarlanır
        2. Port'a bağlanır
        3. Dinleme moduna geçer
        4. Her yeni client için thread oluşturulur
        """
        try:
            # TCP socket oluştur
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(1.0)
            
            # Port'a bağlan
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_clients)
            self.running = True

            Logger.info(f"Server başlatıldı: {self.host}:{self.port} (Max clients: {self.max_clients})", "Server")

            # Client bağlantılarını dinle
            while self.running:
                try:
                    # Maksimum client sayısı kontrolü
                    if len(self.clients) >= self.max_clients:
                        Logger.warning(f"Maksimum client sayısına ulaşıldı: {self.max_clients}", "Server")
                        time.sleep(1)
                        continue
                    
                    # Yeni client bağlantısını kabul et
                    client_socket, client_address = self.socket.accept()
                    client_socket.settimeout(self.timeout)
                    Logger.info(f"Yeni client bağlandı: {client_address}", "Server")
                    
                    # Client bağlantısını logla
                    if self.operation_callback:
                        try:
                            self.operation_callback({
                                'type': 'client_connected',
                                'client': str(client_address),
                                'timestamp': time.time()
                            })
                        except:
                            pass

                    # Her client için ayrı thread oluştur
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    self.clients[client_address] = client_socket

                except socket.timeout:
                    # Timeout normal, devam et
                    continue
                except socket.error as e:
                    if self.running:
                        Logger.error(f"Client kabul etme hatası: {str(e)}", "Server")
                    break

        except Exception as e:
            Logger.error(f"Server başlatma hatası: {str(e)}", "Server")
            raise

    def stop(self):
        """Server'ı durdurur ve tüm bağlantıları kapatır."""
        self.running = False
        if self.socket:
            self.socket.close()
        Logger.info("Server durduruldu", "Server")

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """
        Her client için ayrı thread'de çalışan fonksiyon.
        
        İşlem Adımları:
        1. Client'tan gelen veriyi alır
        2. Paketi parse eder
        3. İşlem tipine göre yönlendirir (PING, ENCRYPT, DECRYPT)
        4. Sonucu client'a gönderir
        """
        try:
            while self.running:
                try:
                    # Paketi al (Robust yöntem)
                    packet_data, packet_type, metadata = DataPacket.receive_packet(client_socket, use_json_format=WIRESHARK_MODE)
                    
                    if packet_type == "DISCONNECTED":
                        break
                        
                    if packet_type == "ERROR":
                        Logger.error(f"Paket alma hatası: {metadata.get('error', 'Bilinmeyen hata')}", "Server")
                        break

                    # PING isteği - Server'ın çalıştığını kontrol etmek için
                    if packet_type == 'PING':
                        self._send_pong(client_socket)
                        continue

                    # HANDSHAKE isteği - RSA public key talep etmek için
                    if packet_type == 'HANDSHAKE':
                        self._send_public_key(client_socket)
                        continue

                    # HYBRID_ENCRYPT isteği - Hibrit şifreleme paketi
                    if packet_type == 'HYBRID_ENCRYPT':
                        self._process_hybrid_request(client_socket, packet_data)
                        continue

                    # ECC_HANDSHAKE isteği - ECC public key talep etmek için
                    if packet_type == 'ECC_HANDSHAKE':
                        self._send_ecc_public_key(client_socket)
                        continue

                    # Şifreleme/deşifreleme isteği
                    if packet_type in ['ENCRYPT', 'DECRYPT']:
                        self._process_request(client_socket, packet_data, packet_type, metadata)
                        continue
                    else:
                        Logger.warning(f"Bilinmeyen paket tipi: {packet_type}", "Server")

                except Exception as e:
                    Logger.error(f"Paket çözme hatası: {str(e)}", "Server")
                    self._send_error(client_socket, f"Paket çözme hatası: {str(e)}")

        except Exception as e:
            Logger.error(f"Client işleme hatası: {str(e)}", "Server")
        finally:
            # Bağlantıyı kapat
            client_socket.close()
            if client_address in self.clients:
                del self.clients[client_address]
            Logger.info(f"Client bağlantısı kapatıldı: {client_address}", "Server")

    def _send_pong(self, client_socket: socket.socket):
        """PING isteğine PONG cevabı gönderir."""
        try:
            pong_metadata = {'type': 'PONG', 'timestamp': time.time()}
            pong_packet = DataPacket.create_packet(b"PONG", 'PONG', pong_metadata, use_json_format=WIRESHARK_MODE)
            client_socket.send(pong_packet)
            if WIRESHARK_MODE:
                Logger.info(f"[WIRESHARK MODE] JSON PONG gönderildi: {pong_packet.decode('utf-8', errors='ignore')[:200]}...", "Server")
        except Exception as e:
            Logger.error(f"Pong gönderme hatası: {str(e)}", "Server")

    def _send_public_key(self, client_socket: socket.socket):
        """HANDSHAKE isteğine RSA public key gönderir."""
        try:
            if not self.key_manager:
                self._send_error(client_socket, "Key manager bulunamadı")
                return
            
            public_key = self.key_manager.get_server_public_key()
            key_metadata = {
                'type': 'PUBLIC_KEY',
                'timestamp': time.time(),
                'key_size': 2048
            }
            key_packet = DataPacket.create_packet(public_key, 'PUBLIC_KEY', key_metadata, use_json_format=WIRESHARK_MODE)
            client_socket.sendall(key_packet)
            Logger.info("RSA public key gönderildi", "Server")
            if WIRESHARK_MODE:
                Logger.info(f"[WIRESHARK MODE] JSON PUBLIC_KEY gönderildi: {key_packet.decode('utf-8', errors='ignore')[:200]}...", "Server")
        except Exception as e:
            Logger.error(f"Public key gönderme hatası: {str(e)}", "Server")
            self._send_error(client_socket, f"Public key gönderme hatası: {str(e)}")

    def _send_ecc_public_key(self, client_socket: socket.socket):
        """ECC_HANDSHAKE isteğine ECC public key gönderir."""
        try:
            if not self.key_manager:
                self._send_error(client_socket, "Key manager bulunamadı")
                return
            
            # ECC anahtar çifti oluştur veya mevcut olanı al (KeyManager üzerinden)
            _, public_key = self.key_manager.generate_ecc_key_pair()
            key_metadata = {
                'type': 'ECC_PUBLIC_KEY',
                'timestamp': time.time()
            }
            key_packet = DataPacket.create_packet(public_key, 'ECC_PUBLIC_KEY', key_metadata, use_json_format=WIRESHARK_MODE)
            client_socket.sendall(key_packet)
            Logger.info("ECC public key gönderildi", "Server")
        except Exception as e:
            Logger.error(f"ECC public key gönderme hatası: {str(e)}", "Server")
            self._send_error(client_socket, f"ECC public key gönderme hatası: {str(e)}")

    def _process_hybrid_request(self, client_socket: socket.socket, packet: bytes):
        """Hibrit şifreleme paketini işler ve sonucu otomatik döndürür."""
        try:
            if not self.hybrid_decryption_manager:
                self._send_error(client_socket, "Hibrit çözme yöneticisi bulunamadı")
                return

            # 1. İşlem Başlangıcını GUI'ye bildir (Etiketlerin güncellenmesi için)
            if self.operation_callback:
                try:
                    # GİRİŞ: Ham JSON Paketi (Şifreli olduğunun kanıtı)
                    input_preview = packet.decode('utf-8', errors='ignore')
                    
                    self.operation_callback({
                        'type': 'operation_start',
                        'client': client_socket.getpeername() if hasattr(client_socket, 'getpeername') else 'Unknown',
                        'operation': 'DECRYPT', # Hibrit paketi çözme işlemi
                        'algorithm': 'hybrid_packet', # Parse edilmeden önceki hali
                        'key': '*** RSA Encrypted ***',
                        'input_data': input_preview,
                        'is_binary': False,
                        'timestamp': time.time()
                    })
                except:
                    pass

            # 2. Paketi Otomatik ÇÖZ
            result_dict = self.hybrid_decryption_manager.decrypt_message(packet, return_dict=True)
            decrypted_message = result_dict['message']
            algorithm = result_dict['algorithm']
            symmetric_key = result_dict['key']

            # 3. İşlem Bilgilerini GUI'ye bildir (MANUEL ÇÖZÜM İÇİN)
            if self.operation_callback:
                try:
                    # Şifreli bileşenleri ayıkla
                    packet_data = self.hybrid_decryption_manager.parse_hybrid_packet(packet)
                    enc_msg_b64 = base64.b64encode(packet_data['encrypted_message']).decode('utf-8')
                    enc_key_b64 = base64.b64encode(packet_data['encrypted_key']).decode('utf-8')
                    key_type = packet_data.get('key_type', 'RSA')

                    self.operation_callback({
                        'type': 'operation_success',
                        'client': client_socket.getpeername() if hasattr(client_socket, 'getpeername') else 'Unknown',
                        'operation': 'HYBRID_MANUAL_FLOW', # Manuel akış tipi
                        'algorithm': algorithm,
                        'key_type': key_type,
                        'input_data': packet.decode('utf-8', errors='ignore'),
                        'encrypted_message': enc_msg_b64,
                        'encrypted_key': enc_key_b64,
                        'timestamp': time.time()
                    })
                except:
                    pass

            # 3. Client'a sonucu döndür (İstemci tarafında görünecek)
            result_metadata = {
                'type': 'RESULT',
                'algorithm': algorithm,
                'operation': 'HYBRID_DECRYPT',
                'timestamp': time.time()
            }
            result_packet = DataPacket.create_packet(decrypted_message, 'RESULT', result_metadata, use_json_format=WIRESHARK_MODE)
            client_socket.sendall(result_packet)
            
            Logger.info(f"Hibrit paket başarıyla çözüldü: {algorithm}", "Server")
            
        except Exception as e:
            Logger.error(f"Hibrit paket işleme hatası: {str(e)}", "Server")
            self._send_error(client_socket, f"Hibrit paket işleme hatası: {str(e)}")

    def decrypt_manual(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Saklanan paketi manuel olarak çözer.
        
        Args:
            packet_data: Parse edilmiş paket verisi
            
        Returns:
            Dict: Çözülmüş mesaj ve anahtar bilgisi
        """
        if not self.hybrid_decryption_manager:
            raise ValueError("Hibrit çözme yöneticisi bulunamadı")
            
        return self.hybrid_decryption_manager.decrypt_message(packet_data['raw_packet'], return_dict=True)

    def _process_request(self, client_socket: socket.socket, data: bytes,
                        operation: str, metadata: Dict[str, Any]):
        """
        Şifreleme/deşifreleme isteğini işler.
        
        İşlem Adımları:
        1. Metadata'dan algoritma ve anahtarı alır
        2. ProcessingManager'a yönlendir
        3. Sonucu client'a gönderir
        
        ÖNEMLİ: Tüm şifreleme işlemi burada yapılır!
        """
        try:
            # Metadata'dan bilgileri al
            algorithm = metadata.get('algorithm', 'caesar')
            key = metadata.get('key', '')

            Logger.info(f"İşlem talebi: {operation} - {algorithm}", "Server")

            # Veri kontrolü
            if not data:
                self._send_error(client_socket, "Veri boş olamaz")
                return

            # Anahtar kontrolü (bazı algoritmalar anahtar gerektirmez)
            if not key and algorithm not in ['polybius']:
                self._send_error(client_socket, "Anahtar boş olamaz")
                return

            # İşlem başlangıcını logla
            if self.operation_callback:
                try:
                    # Veri önizleme (Text veya Hex)
                    data_preview = ""
                    is_binary = False
                    try:
                        data_preview = data.decode('utf-8')
                    except:
                        data_preview = base64.b64encode(data).decode('utf-8')
                        is_binary = True

                    # Metadata'dan dosya bilgilerini al
                    filename = metadata.get('filename', '')
                    file_extension = metadata.get('extension', '')
                    file_size = metadata.get('file_size', 0)
                    
                    self.operation_callback({
                        'type': 'operation_start',
                        'client': client_socket.getpeername() if hasattr(client_socket, 'getpeername') else 'Unknown',
                        'operation': operation,
                        'algorithm': algorithm,
                        'key': key,
                        'input_data': data_preview,
                        'is_binary': is_binary,
                        'data_size': len(data),
                        'filename': filename,
                        'extension': file_extension,
                        'file_size': file_size if file_size > 0 else len(data),
                        'timestamp': time.time()
                    })
                except:
                    pass

            # ProcessingManager'a yönlendir (ŞİFRELEME İŞLEMİ BURADA YAPILIR!)
            if self.processing_callback:
                result = self.processing_callback(data, operation, algorithm, key, metadata)

                # Başarılı sonuç
                if result and result.get('success'):
                    if WIRESHARK_MODE:
                        # Wireshark modu: JSON formatında cevap gönder
                        result_packet = DataPacket.create_json_response(
                            result['data'], 'RESULT', algorithm, success=True
                        )
                        client_socket.sendall(result_packet)
                        Logger.info(f"[WIRESHARK MODE] JSON cevap gönderildi: {result_packet.decode('utf-8', errors='ignore')[:200]}...", "Server")
                    else:
                        # Normal mod: Binary paket formatı
                        result_metadata = {
                            'type': 'RESULT',
                            'algorithm': algorithm,
                            'operation': operation,
                            'timestamp': time.time()
                        }
                        result_packet = DataPacket.create_packet(result['data'], 'RESULT', result_metadata)
                        client_socket.sendall(result_packet)
                    Logger.info(f"İşlem tamamlandı: {operation} - {algorithm}", "Server")
                    
                    # İşlem başarısını logla
                    if self.operation_callback:
                        try:
                            # Sonuç verisi önizleme
                            result_data = result.get('data', b'')
                            result_preview = ""
                            res_is_binary = False
                            try:
                                result_preview = result_data.decode('utf-8')
                            except:
                                result_preview = base64.b64encode(result_data).decode('utf-8')
                                res_is_binary = True

                            # Metadata'dan dosya bilgilerini al
                            filename = metadata.get('filename', '')
                            file_extension = metadata.get('extension', '')
                            file_size = metadata.get('file_size', 0)
                            
                            self.operation_callback({
                                'type': 'operation_success',
                                'client': client_socket.getpeername() if hasattr(client_socket, 'getpeername') else 'Unknown',
                                'operation': operation,
                                'algorithm': algorithm,
                                'key': key,
                                'input_data': data_preview,
                                'output_data': result_preview,
                                'is_binary': is_binary,
                                'res_is_binary': res_is_binary,
                                'data_size': len(data),
                                'result_size': len(result_data),
                                'filename': filename,
                                'extension': file_extension,
                                'file_size': file_size if file_size > 0 else len(data),
                                'timestamp': time.time()
                            })
                        except:
                            pass
                else:
                    # Hata durumu
                    error_msg = result.get('error', 'İşlem başarısız') if result else 'İşlem başarısız'
                    Logger.warning(f"İşlem başarısız: {error_msg}", "Server")
                    self._send_error(client_socket, error_msg)
                    
                    # İşlem hatasını logla
                    if self.operation_callback:
                        try:
                            self.operation_callback({
                                'type': 'operation_error',
                                'client': client_socket.getpeername() if hasattr(client_socket, 'getpeername') else 'Unknown',
                                'operation': operation,
                                'algorithm': algorithm,
                                'key': key,
                                'error': error_msg,
                                'timestamp': time.time()
                            })
                        except:
                            pass
            else:
                Logger.error("ProcessingManager bulunamadı", "Server")
                self._send_error(client_socket, "ProcessingManager bulunamadı")

        except Exception as e:
            Logger.error(f"İşlem hatası: {str(e)}", "Server")
            import traceback
            Logger.debug(f"Detaylı hata: {traceback.format_exc()}", "Server")
            self._send_error(client_socket, f"İşlem hatası: {str(e)}")

    def _send_error(self, client_socket: socket.socket, error_message: str):
        """Client'a hata mesajı gönderir."""
        try:
            if WIRESHARK_MODE:
                # Wireshark modu: JSON formatında hata gönder
                error_packet = DataPacket.create_json_response(
                    b"", 'ERROR', '', success=False, error=error_message
                )
                client_socket.sendall(error_packet)
                Logger.info(f"[WIRESHARK MODE] JSON hata gönderildi: {error_packet.decode('utf-8', errors='ignore')[:200]}...", "Server")
            else:
                # Normal mod: Binary paket formatı
                error_metadata = {
                    'type': 'ERROR',
                    'error': error_message,
                    'timestamp': time.time()
                }
                error_packet = DataPacket.create_packet(b"", 'ERROR', error_metadata)
                client_socket.sendall(error_packet)
        except Exception as e:
            Logger.error(f"Hata gönderme hatası: {str(e)}", "Server")

    def set_processing_callback(self, callback: Callable):
        """
        Şifreleme işlemlerini yapan callback fonksiyonunu ayarlar.
        
        Bu callback genellikle ProcessingManager.process_request olur.
        """
        self.processing_callback = callback

    def set_key_manager(self, key_manager):
        """RSA anahtar yönetimini ayarlar."""
        self.key_manager = key_manager
        if key_manager:
            from server.hybrid_decryption import HybridDecryptionManager
            self.hybrid_decryption_manager = HybridDecryptionManager(key_manager)
    
    def set_operation_callback(self, callback: Callable):
        """İşlem logları için callback fonksiyonunu ayarlar."""
        self.operation_callback = callback

    def get_client_count(self) -> int:
        """Bağlı client sayısını döndürür."""
        return len(self.clients)

    def is_running(self) -> bool:
        """Server'ın çalışıp çalışmadığını kontrol eder."""
        return self.running
