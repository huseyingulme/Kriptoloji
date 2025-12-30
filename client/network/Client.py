"""
Client - Server'a Bağlanan ve İstek Gönderen Sınıf

Bu sınıf, kullanıcının bilgisayarında (client) çalışır ve server'a bağlanır.
Kullanıcıdan alınan verileri server'a gönderir ve şifrelenmiş sonuçları alır.

ÖNEMLİ: Client tarafında şifreleme yapılmaz! Tüm işlemler server'da yapılır.
"""

import socket
import threading
import time
from typing import Optional, Callable, Dict, Any
from shared.utils import DataPacket, Logger
from shared.error_handler import ErrorHandler, AutoReconnect
from config import config_manager

# Wireshark modunu kontrol et
WIRESHARK_MODE = config_manager.get("features.wireshark_mode", False)


class Client:
    """
    Server'a bağlanan ve şifreleme istekleri gönderen client sınıfı.
    
    Görevleri:
    1. Server'a bağlanmak
    2. Kullanıcı verilerini server'a göndermek
    3. Server'dan gelen şifrelenmiş sonuçları almak
    4. Bağlantı hatalarını yönetmek
    """

    def __init__(self, host: str = None, port: int = None):
        """
        Client'ı başlatır.
        
        Args:
            host: Server IP adresi (varsayılan: config'den alınır)
            port: Server port numarası (varsayılan: config'den alınır)
        """
        self.host = host or config_manager.get("client.default_host", "localhost")
        self.port = port or config_manager.get("client.default_port", 12345)
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.response_callback: Optional[Callable] = None
        self.error_callback: Optional[Callable] = None
        self.connection_timeout = config_manager.get("client.connection_timeout", 10)
        self.retry_attempts = config_manager.get("client.retry_attempts", 3)
        self.retry_delay = config_manager.get("client.retry_delay", 1.0)
        self.auto_reconnect = config_manager.get("client.auto_reconnect", True)

    @ErrorHandler.retry(max_attempts=3, delay=1.0, exceptions=(ConnectionError, OSError, TimeoutError))
    def connect(self) -> bool:
        """
        Server'a bağlanır.
        
        İşlem Adımları:
        1. Socket oluşturulur
        2. Timeout ayarlanır
        3. Server'a bağlantı kurulur
        4. Bağlantı durumu kaydedilir
        
        Returns:
            bool: Bağlantı başarılı ise True
        """
        try:
            # TCP socket oluştur
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)
            
            # Server'a bağlan
            self.socket.connect((self.host, self.port))
            self.connected = True

            Logger.info(f"Server'a bağlandı: {self.host}:{self.port}", "Client")
            return True

        except Exception as e:
            Logger.error(f"Bağlantı hatası: {str(e)}", "Client")
            self.connected = False
            raise

    def disconnect(self):
        """Server bağlantısını kapatır."""
        try:
            if self.socket:
                self.socket.close()
            self.connected = False
            Logger.info("Server bağlantısı kapatıldı", "Client")
        except Exception as e:
            Logger.error(f"Bağlantı kapatma hatası: {str(e)}", "Client")

    def send_request(self, data: bytes, operation: str, algorithm: str, key: str,
                   metadata: Dict[str, Any] = None) -> bool:
        """
        Server'a şifreleme/deşifreleme isteği gönderir.
        
        İşlem Adımları:
        1. Bağlantı kontrolü yapılır
        2. İstek paketi oluşturulur (veri + algoritma + anahtar)
        3. Büyük veriler parçalara bölünür (chunking)
        4. Paket server'a gönderilir
        
        Args:
            data: Şifrelenecek/deşifrelenecek veri (bytes)
            operation: İşlem tipi ('ENCRYPT' veya 'DECRYPT')
            algorithm: Kullanılacak algoritma adı
            key: Şifreleme anahtarı
            metadata: Ek bilgiler (opsiyonel)
            
        Returns:
            bool: İstek başarıyla gönderildiyse True
        """
        if not self.connected:
            Logger.error("Server bağlantısı yok", "Client")
            return False

        try:
            # Metadata hazırla
            if metadata is None:
                metadata = {}

            metadata.update({
                'type': operation,
                'algorithm': algorithm,
                'key': key,
                'timestamp': time.time()
            })

            # Paket oluştur (Wireshark modu kontrolü)
            packet = DataPacket.create_packet(data, operation, metadata, use_json_format=WIRESHARK_MODE)

            # Paketi gönder (TCP sendall her şeyi halleder)
            self.socket.sendall(packet)
            
            if WIRESHARK_MODE:
                Logger.info(f"[WIRESHARK MODE] JSON paket gönderildi: {packet.decode('utf-8', errors='ignore')[:200]}...", "Client")

            Logger.info(f"İşlem talebi gönderildi: {operation} - {algorithm}", "Client")
            return True

        except Exception as e:
            Logger.error(f"Veri gönderme hatası: {str(e)}", "Client")
            return False

    def send_hybrid_packet(self, packet: bytes) -> Optional[Dict[str, Any]]:
        """
        Hibrit şifreleme paketini gönderir.
        
        Args:
            packet: Hibrit şifreleme paketi (JSON bytes)
            
        Returns:
            Dict: Server cevabı
        """
        if not self.connected:
            Logger.error("Server bağlantısı yok", "Client")
            return None

        try:
            # Hibrit paketi gönder
            metadata = {'type': 'HYBRID_ENCRYPT', 'timestamp': time.time()}
            hybrid_packet = DataPacket.create_packet(packet, 'HYBRID_ENCRYPT', metadata)
            
            # Direkt gönder
            self.socket.sendall(hybrid_packet)

            Logger.info("Hibrit paket gönderildi", "Client")
            
            # Cevap al
            return self.receive_response()

        except Exception as e:
            Logger.error(f"Hibrit paket gönderme hatası: {str(e)}", "Client")
            return None

    def receive_response(self) -> Optional[Dict[str, Any]]:
        """
        Server'dan gelen cevabı alır.
        
        İşlem Adımları:
        1. Server'dan veri alınır
        2. Paket parse edilir
        3. Parçalı veriler birleştirilir (gerekirse)
        4. Sonuç döndürülür
        
        Returns:
            Dict: Server cevabı (success, data, error vb.)
        """
        if not self.connected:
            Logger.error("Server bağlantısı yok", "Client")
            return None

        try:
            # Paketi al (Robust yöntem)
            data, packet_type, metadata = DataPacket.receive_packet(self.socket, use_json_format=WIRESHARK_MODE)

            if packet_type == "DISCONNECTED":
                self.connected = False
                return None
                
            if packet_type == "ERROR" and not data:
                return {
                    'success': False,
                    'error': metadata.get('error', 'Bilinmeyen server hatası'),
                    'type': 'ERROR'
                }

            # Başarı kontrolü
            is_success = packet_type in ['RESULT', 'SUCCESS', 'PONG', 'PUBLIC_KEY', 'ECC_PUBLIC_KEY', 'ACK'] and packet_type not in ['ERROR', 'FAILED']
            
            # Cevap oluştur
            response = {
                'data': data,
                'type': packet_type,
                'metadata': metadata,
                'success': is_success
            }
            
            # Hata durumunda error mesajını ekle
            if not is_success and metadata:
                if 'error' in metadata:
                    response['error'] = metadata['error']
                else:
                    response['error'] = f"Server hatası: {packet_type}"

            if is_success:
                Logger.info(f"Server cevabı alındı: {packet_type}", "Client")
            else:
                error_msg = response.get('error', 'Bilinmeyen hata')
                Logger.warning(f"Server hatası: {error_msg}", "Client")
            
            return response

        except Exception as e:
            Logger.error(f"Cevap alma hatası: {str(e)}", "Client")
            return None

    def process_request(self, data: bytes, operation: str, algorithm: str, key: str,
                      metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Tam işlem döngüsü: İstek gönder + Cevap al
        
        Bu fonksiyon, şifreleme/deşifreleme isteğini gönderir ve sonucu alır.
        Otomatik yeniden bağlanma özelliği vardır.
        
        Args:
            data: İşlenecek veri
            operation: İşlem tipi
            algorithm: Algoritma adı
            key: Anahtar
            metadata: Ek bilgiler
            
        Returns:
            Dict: İşlem sonucu
        """
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            try:
                # Bağlantı kontrolü
                if not self.connected:
                    if not self.connect():
                        attempt += 1
                        if attempt >= max_attempts:
                            return {
                                'success': False,
                                'error': f"Server'a bağlanılamadı. Lütfen server'ın çalıştığından emin olun. (Deneme: {attempt}/{max_attempts})"
                            }
                        time.sleep(2.0)
                        continue

                # İstek gönder
                if not self.send_request(data, operation, algorithm, key, metadata):
                    attempt += 1
                    if attempt >= max_attempts:
                        return {
                            'success': False,
                            'error': f"İstek gönderilemedi. (Deneme: {attempt}/{max_attempts})"
                        }
                    # Bağlantıyı kapat ve yeniden dene
                    self.disconnect()
                    time.sleep(2.0)
                    continue

                # Cevap al
                response = self.receive_response()
                
                if response is None:
                    attempt += 1
                    if attempt >= max_attempts:
                        return {
                            'success': False,
                            'error': f"Server'dan cevap alınamadı. (Deneme: {attempt}/{max_attempts})"
                        }
                    # Bağlantıyı kapat ve yeniden dene
                    self.disconnect()
                    time.sleep(2.0)
                    continue

                # Callback çağır (varsa)
                if response and self.response_callback:
                    self.response_callback(response)

                return response
                
            except (ConnectionError, OSError, TimeoutError) as e:
                attempt += 1
                Logger.warning(f"Bağlantı hatası (Deneme {attempt}/{max_attempts}): {str(e)}", "Client")
                
                if attempt >= max_attempts:
                    return {
                        'success': False,
                        'error': f"Bağlantı hatası: {str(e)}. Maksimum deneme sayısına ulaşıldı ({max_attempts}). Lütfen server'ın çalıştığından emin olun."
                    }
                
                # Bağlantıyı kapat ve yeniden dene
                self.disconnect()
                time.sleep(2.0)
        
        return {
            'success': False,
            'error': f"Maksimum yeniden bağlanma denemesi aşıldı ({max_attempts}). Lütfen server'ın çalıştığından emin olun."
        }

    def set_response_callback(self, callback: Callable):
        """Cevap geldiğinde çağrılacak callback fonksiyonunu ayarlar."""
        self.response_callback = callback

    def set_error_callback(self, callback: Callable):
        """Hata durumunda çağrılacak callback fonksiyonunu ayarlar."""
        self.error_callback = callback

    def is_connected(self) -> bool:
        """Bağlantı durumunu kontrol eder."""
        return self.connected

    def ping_server(self) -> bool:
        """
        Server'ın çalışıp çalışmadığını kontrol eder (ping).
        
        Returns:
            bool: Server cevap veriyorsa True
        """
        try:
            if not self.connected:
                if not self.connect():
                    return False

            # Ping paketi gönder
            ping_data = b"PING"
            ping_metadata = {'type': 'PING', 'timestamp': time.time()}
            packet = DataPacket.create_packet(ping_data, 'PING', ping_metadata, use_json_format=WIRESHARK_MODE)

            self.socket.sendall(packet)

            # Pong cevabı bekle (Robust yöntem)
            _, packet_type, _ = DataPacket.receive_packet(self.socket, use_json_format=WIRESHARK_MODE)
            return packet_type == 'PONG'

        except Exception as e:
            Logger.error(f"Ping hatası: {str(e)}", "Client")
            return False

    def request_public_key(self) -> Optional[bytes]:
        """
        Server'dan RSA public key talep eder (handshake).
        
        Returns:
            bytes: RSA public key (PEM formatında) veya None
        """
        try:
            if not self.connected:
                if not self.connect():
                    return None

            # Handshake paketi gönder
            handshake_data = b"HANDSHAKE"
            handshake_metadata = {'type': 'HANDSHAKE', 'timestamp': time.time()}
            packet = DataPacket.create_packet(handshake_data, 'HANDSHAKE', handshake_metadata, use_json_format=WIRESHARK_MODE)

            self.socket.sendall(packet)

            # Public key cevabı bekle (Robust yöntem)
            data, packet_type, metadata = DataPacket.receive_packet(self.socket, use_json_format=WIRESHARK_MODE)
            if packet_type == 'PUBLIC_KEY':
                Logger.info("RSA public key alındı", "Client")
                return data
            else:
                Logger.warning(f"Beklenmeyen paket tipi: {packet_type}", "Client")
                return None

        except Exception as e:
            Logger.error(f"Handshake hatası: {str(e)}", "Client")
            return None

    def request_ecc_public_key(self) -> Optional[bytes]:
        """
        Server'dan ECC public key talep eder.
        
        Returns:
            bytes: ECC public key (PEM formatında) veya None
        """
        try:
            if not self.connected:
                if not self.connect():
                    return None

            # ECC Handshake paketi gönder
            handshake_data = b"ECC_HANDSHAKE"
            handshake_metadata = {'type': 'ECC_HANDSHAKE', 'timestamp': time.time()}
            packet = DataPacket.create_packet(handshake_data, 'ECC_HANDSHAKE', handshake_metadata, use_json_format=WIRESHARK_MODE)

            self.socket.sendall(packet)

            # Public key cevabı bekle
            data, packet_type, metadata = DataPacket.receive_packet(self.socket, use_json_format=WIRESHARK_MODE)
            if packet_type == 'ECC_PUBLIC_KEY':
                Logger.info("ECC public key alındı", "Client")
                return data
            else:
                Logger.warning(f"Beklenmeyen paket tipi: {packet_type}", "Client")
                return None

        except Exception as e:
            Logger.error(f"ECC Handshake hatası: {str(e)}", "Client")
            return None