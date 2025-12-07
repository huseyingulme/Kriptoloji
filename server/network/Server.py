import socket
import threading
import time
from typing import Optional, Dict, Any, Callable
from shared.utils import DataPacket, Logger
from config import config_manager

class Server:

    def __init__(self, host: str = None, port: int = None):

        self.host = host or config_manager.get("server.host", "localhost")
        self.port = port or config_manager.get("server.port", 12345)
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.clients = []
        self.processing_callback: Optional[Callable] = None
        self.max_clients = config_manager.get("server.max_clients", 10)
        self.timeout = config_manager.get("server.timeout", 30)

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(1.0)
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_clients)
            self.running = True

            Logger.info(f"Server başlatıldı: {self.host}:{self.port} (Max clients: {self.max_clients})", "Server")

            while self.running:
                try:
                    if len(self.clients) >= self.max_clients:
                        Logger.warning(f"Maksimum client sayısına ulaşıldı: {self.max_clients}", "Server")
                        time.sleep(1)
                        continue
                    
                    client_socket, client_address = self.socket.accept()
                    client_socket.settimeout(self.timeout)
                    Logger.info(f"Yeni client bağlandı: {client_address}", "Server")

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    self.clients.append((client_socket, client_address))

                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.running:
                        Logger.error(f"Client kabul etme hatası: {str(e)}", "Server")
                    break

        except Exception as e:
            Logger.error(f"Server başlatma hatası: {str(e)}", "Server")
            raise

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        Logger.info("Server durduruldu", "Server")

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break

                try:
                    packet_data, packet_type, metadata = DataPacket.parse_packet(data)

                    if packet_type == 'PING':
                        self._send_pong(client_socket)
                        continue

                    if packet_type == 'CHUNK':
                        chunks = [data]
                        while len(chunks) < metadata.get('total_chunks', 1):
                            chunk_data = client_socket.recv(4096)
                            if chunk_data:
                                chunks.append(chunk_data)

                        packet_data = DataPacket.reassemble_chunks(chunks)
                        _, packet_type, metadata = DataPacket.parse_packet(packet_data)

                    if packet_type in ['ENCRYPT', 'DECRYPT']:
                        self._process_request(client_socket, packet_data, packet_type, metadata)
                    else:
                        Logger.warning(f"Bilinmeyen paket tipi: {packet_type}", "Server")

                except Exception as e:
                    Logger.error(f"Paket çözme hatası: {str(e)}", "Server")
                    self._send_error(client_socket, f"Paket çözme hatası: {str(e)}")

        except Exception as e:
            Logger.error(f"Client işleme hatası: {str(e)}", "Server")
        finally:
            client_socket.close()
            if (client_socket, client_address) in self.clients:
                self.clients.remove((client_socket, client_address))
            Logger.info(f"Client bağlantısı kapatıldı: {client_address}", "Server")

    def _send_pong(self, client_socket: socket.socket):
        try:
            pong_metadata = {'type': 'PONG', 'timestamp': time.time()}
            pong_packet = DataPacket.create_packet(b"PONG", 'PONG', pong_metadata)
            client_socket.send(pong_packet)
        except Exception as e:
            Logger.error(f"Pong gönderme hatası: {str(e)}", "Server")

    def _process_request(self, client_socket: socket.socket, data: bytes,
                        operation: str, metadata: Dict[str, Any]):
        try:
            algorithm = metadata.get('algorithm', 'caesar')
            key = metadata.get('key', '')

            Logger.info(f"İşlem talebi: {operation} - {algorithm}", "Server")

            if not data:
                self._send_error(client_socket, "Veri boş olamaz")
                return

            if not key and algorithm not in ['polybius']:
                self._send_error(client_socket, "Anahtar boş olamaz")
                return

            if self.processing_callback:
                result = self.processing_callback(data, operation, algorithm, key, metadata)

                if result and result.get('success'):
                    result_metadata = {
                        'type': 'RESULT',
                        'algorithm': algorithm,
                        'operation': operation,
                        'timestamp': time.time()
                    }
                    result_packet = DataPacket.create_packet(result['data'], 'RESULT', result_metadata)
                    client_socket.sendall(result_packet)
                    Logger.info(f"İşlem tamamlandı: {operation} - {algorithm}", "Server")
                else:
                    error_msg = result.get('error', 'İşlem başarısız') if result else 'İşlem başarısız'
                    Logger.warning(f"İşlem başarısız: {error_msg}", "Server")
                    self._send_error(client_socket, error_msg)
            else:
                Logger.error("ProcessingManager bulunamadı", "Server")
                self._send_error(client_socket, "ProcessingManager bulunamadı")

        except Exception as e:
            Logger.error(f"İşlem hatası: {str(e)}", "Server")
            import traceback
            Logger.debug(f"Detaylı hata: {traceback.format_exc()}", "Server")
            self._send_error(client_socket, f"İşlem hatası: {str(e)}")

    def _send_error(self, client_socket: socket.socket, error_message: str):
        try:
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
        self.processing_callback = callback

    def get_client_count(self) -> int:
        return len(self.clients)

    def is_running(self) -> bool:
        return self.running
