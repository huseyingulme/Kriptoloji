import socket
import threading
import time
from typing import Optional, Callable, Dict, Any
from shared.utils import DataPacket, Logger
from shared.error_handler import ErrorHandler, AutoReconnect
from config import config_manager

class Client:

    def __init__(self, host: str = None, port: int = None):

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

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)
            self.socket.connect((self.host, self.port))
            self.connected = True

            Logger.info(f"Server'a bağlandı: {self.host}:{self.port}", "Client")
            return True

        except Exception as e:
            Logger.error(f"Bağlantı hatası: {str(e)}", "Client")
            self.connected = False
            raise

    def disconnect(self):
        try:
            if self.socket:
                self.socket.close()
            self.connected = False
            Logger.info("Server bağlantısı kapatıldı", "Client")
        except Exception as e:
            Logger.error(f"Bağlantı kapatma hatası: {str(e)}", "Client")

    def send_request(self, data: bytes, operation: str, algorithm: str, key: str,
                   metadata: Dict[str, Any] = None) -> bool:

        if not self.connected:
            Logger.error("Server bağlantısı yok", "Client")
            return False

        try:
            if metadata is None:
                metadata = {}

            metadata.update({
                'type': operation,
                'algorithm': algorithm,
                'key': key,
                'timestamp': time.time()
            })

            packet = DataPacket.create_packet(data, operation, metadata)

            if len(packet) > 1024:
                chunks = DataPacket.create_chunked_packet(packet, 1024)

                for i, chunk in enumerate(chunks):
                    self.socket.send(chunk)
                    Logger.debug(f"Chunk {i+1}/{len(chunks)} gönderildi", "Client")
            else:
                self.socket.send(packet)

            Logger.info(f"İşlem talebi gönderildi: {operation} - {algorithm}", "Client")
            return True

        except Exception as e:
            Logger.error(f"Veri gönderme hatası: {str(e)}", "Client")
            return False

    def receive_response(self) -> Optional[Dict[str, Any]]:

        if not self.connected:
            Logger.error("Server bağlantısı yok", "Client")
            return None

        try:
            response_data = self.socket.recv(4096)

            if not response_data:
                Logger.warning("Server'dan boş cevap alındı", "Client")
                return None

            data, packet_type, metadata = DataPacket.parse_packet(response_data)

            if packet_type == 'CHUNK':
                chunks = [response_data]

                while len(chunks) < metadata.get('total_chunks', 1):
                    chunk_data = self.socket.recv(4096)
                    if chunk_data:
                        chunks.append(chunk_data)

                data = DataPacket.reassemble_chunks(chunks)
                _, packet_type, metadata = DataPacket.parse_packet(data)

            is_success = packet_type not in ['ERROR', 'FAILED']
            
            response = {
                'data': data,
                'type': packet_type,
                'metadata': metadata,
                'success': is_success
            }
            
            # Hata durumunda error mesajını metadata'dan al
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

    @AutoReconnect(max_attempts=5, delay=2.0)
    def process_request(self, data: bytes, operation: str, algorithm: str, key: str,
                      metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:

        if not self.connected:
            if not self.connect():
                return None

        if not self.send_request(data, operation, algorithm, key, metadata):
            if self.auto_reconnect:
                raise ConnectionError("İstek gönderilemedi")
            return None

        response = self.receive_response()

        if response and self.response_callback:
            self.response_callback(response)

        return response

    def set_response_callback(self, callback: Callable):
        self.response_callback = callback

    def set_error_callback(self, callback: Callable):
        self.error_callback = callback

    def is_connected(self) -> bool:
        return self.connected

    def ping_server(self) -> bool:
        try:
            if not self.connected:
                if not self.connect():
                    return False

            ping_data = b"PING"
            ping_metadata = {'type': 'PING', 'timestamp': time.time()}
            packet = DataPacket.create_packet(ping_data, 'PING', ping_metadata)

            self.socket.send(packet)

            response = self.socket.recv(1024)
            if response:
                _, packet_type, _ = DataPacket.parse_packet(response)
                return packet_type == 'PONG'

            return False

        except Exception as e:
            Logger.error(f"Ping hatası: {str(e)}", "Client")
            return False
