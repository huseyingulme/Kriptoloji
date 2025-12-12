import json
import struct
import hashlib
import os
from typing import Dict, Any, Tuple, List

class DataPacket:

    @staticmethod
    def create_packet(data: bytes, packet_type: str, metadata: Dict[str, Any] = None, use_json_format: bool = False) -> bytes:
        """
        Paket oluşturur.
        
        Args:
            data: Gönderilecek veri (bytes)
            packet_type: Paket tipi (ENCRYPT, DECRYPT, vb.)
            metadata: Ek metadata bilgileri
            use_json_format: True ise Wireshark için JSON formatında gönderir
        
        Returns:
            bytes: Oluşturulan paket
        """
        if metadata is None:
            metadata = {}

        # Wireshark modu: JSON formatında açık metin gönder
        if use_json_format:
            # Veriyi string'e çevir (base64 encode edilmiş olabilir)
            try:
                message_str = data.decode('utf-8', errors='ignore')
            except:
                import base64
                message_str = base64.b64encode(data).decode('utf-8')
            
            # JSON paket oluştur (Wireshark uyumlu format)
            # Format: {"operation":"ENCRYPT/DECRYPT","message":"...","algorithm":"...","key":"...","timestamp":...}
            # Alan sırası: operation, message, algorithm, key, timestamp (diğer alanlar sonra)
            json_packet = {}
            
            # Zorunlu alanlar (sıralı)
            json_packet["operation"] = packet_type  # ENCRYPT, DECRYPT, PING, HANDSHAKE, vb.
            json_packet["message"] = message_str
            json_packet["algorithm"] = metadata.get('algorithm', '')
            json_packet["key"] = metadata.get('key', '')
            json_packet["timestamp"] = metadata.get('timestamp', 0)
            
            # Ek metadata bilgilerini ekle (sadece önemli olanlar, alfabetik sırada)
            extra_keys = []
            for key, value in metadata.items():
                if key not in ['algorithm', 'key', 'timestamp', 'type'] and value:
                    # Sadece string, number, bool gibi JSON uyumlu değerleri ekle
                    if isinstance(value, (str, int, float, bool)):
                        extra_keys.append((key, value))
            
            # Ek alanları alfabetik sırada ekle
            for key, value in sorted(extra_keys):
                json_packet[key] = value
            
            # JSON string (compact format, Wireshark için optimize edilmiş)
            json_str = json.dumps(json_packet, ensure_ascii=False, separators=(',', ':'))
            return json_str.encode('utf-8')

        # Normal mod: Binary paket formatı
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_size = len(metadata_json)

        packet = struct.pack('!II', len(data), metadata_size)
        packet += metadata_json
        packet += data

        return packet

    @staticmethod
    def parse_packet(packet: bytes, use_json_format: bool = False) -> Tuple[bytes, str, Dict[str, Any]]:
        """
        Paketi parse eder.
        
        Args:
            packet: Parse edilecek paket (bytes)
            use_json_format: True ise JSON formatında paket beklenir
        
        Returns:
            Tuple[bytes, str, Dict]: (data, packet_type, metadata)
        """
        # Wireshark modu: JSON formatında paket
        if use_json_format:
            try:
                # JSON parse et (newline varsa kaldır)
                packet_str = packet.decode('utf-8').strip()
                json_data = json.loads(packet_str)
                
                # JSON'dan bilgileri çıkar (Wireshark uyumlu format)
                # Format: {"operation": "ENCRYPT/DECRYPT", "message": "...", "algorithm": "...", "key": "...", "timestamp": ...}
                message_str = json_data.get('message', '')
                algorithm = json_data.get('algorithm', '')
                key = json_data.get('key', '')
                
                # Mesajı bytes'a çevir
                try:
                    data = message_str.encode('utf-8')
                except:
                    import base64
                    try:
                        data = base64.b64decode(message_str)
                    except:
                        data = message_str.encode('utf-8', errors='ignore')
                
                # Paket tipini belirle (operation'dan al, yoksa type'dan, yoksa default ENCRYPT)
                packet_type = json_data.get('operation') or json_data.get('type', 'ENCRYPT')
                
                # Metadata oluştur (mevcut sistemle uyumlu)
                metadata = {
                    'type': packet_type,
                    'algorithm': algorithm,
                    'key': key,
                    'timestamp': json_data.get('timestamp', 0)
                }
                
                # Ek metadata bilgilerini ekle
                for key, value in json_data.items():
                    if key not in ['operation', 'message', 'algorithm', 'key', 'timestamp', 'type']:
                        metadata[key] = value
                
                return data, packet_type, metadata
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON parse hatası: {str(e)}")

        # Normal mod: Binary paket formatı
        if len(packet) < 8:
            raise ValueError("Geçersiz paket boyutu")

        data_size, metadata_size = struct.unpack('!II', packet[:8])

        if len(packet) < 8 + metadata_size + data_size:
            raise ValueError("Eksik paket verisi")

        metadata_json = packet[8:8+metadata_size].decode('utf-8')
        metadata = json.loads(metadata_json)

        data = packet[8+metadata_size:8+metadata_size+data_size]

        return data, metadata.get('type', 'UNKNOWN'), metadata

    @staticmethod
    def create_chunked_packet(data: bytes, chunk_size: int = 1024) -> List[bytes]:
        chunks = []
        total_chunks = (len(data) + chunk_size - 1) // chunk_size

        for i in range(0, len(data), chunk_size):
            chunk_data = data[i:i+chunk_size]
            metadata = {
                'type': 'CHUNK',
                'chunk_index': i // chunk_size,
                'total_chunks': total_chunks,
                'chunk_size': len(chunk_data)
            }
            chunk = DataPacket.create_packet(chunk_data, 'CHUNK', metadata)
            chunks.append(chunk)

        return chunks

    @staticmethod
    def create_json_response(result_data: bytes, packet_type: str, algorithm: str, success: bool = True, error: str = None) -> bytes:
        """
        Wireshark için JSON formatında cevap paketi oluşturur.
        
        Args:
            result_data: Sonuç verisi (bytes)
            packet_type: Paket tipi (RESULT, ERROR, vb.)
            algorithm: Kullanılan algoritma
            success: İşlem başarılı mı?
            error: Hata mesajı (varsa)
        
        Returns:
            bytes: JSON formatında cevap paketi
        """
        try:
            result_str = result_data.decode('utf-8', errors='ignore')
        except:
            import base64
            result_str = base64.b64encode(result_data).decode('utf-8')
        
        # Wireshark uyumlu cevap formatı
        # Format: {"operation":"RESULT/ERROR","message":"...","algorithm":"...","success":true/false,"timestamp":...}
        # Alan sırası: operation, message, algorithm, success, timestamp, error (varsa)
        import time
        json_response = {}
        
        # Zorunlu alanlar (sıralı)
        json_response["operation"] = packet_type  # RESULT, ERROR, vb.
        json_response["message"] = result_str
        json_response["algorithm"] = algorithm
        json_response["success"] = success
        json_response["timestamp"] = time.time()
        
        # Hata varsa ekle
        if not success and error:
            json_response["error"] = error
        
        # JSON string (compact format, Wireshark için optimize edilmiş)
        json_str = json.dumps(json_response, ensure_ascii=False, separators=(',', ':'))
        return json_str.encode('utf-8')

    @staticmethod
    def reassemble_chunks(chunks: List[bytes]) -> bytes:
        if not chunks:
            return b''

        parsed_chunks = []
        for chunk in chunks:
            data, _, metadata = DataPacket.parse_packet(chunk)
            parsed_chunks.append((metadata['chunk_index'], data))

        parsed_chunks.sort(key=lambda x: x[0])

        return b''.join([chunk_data for _, chunk_data in parsed_chunks])

class FileUtils:

    SUPPORTED_FORMATS = {
        'text': ['.txt', '.md', '.py', '.js', '.html', '.css'],
        'image': ['.png', '.jpg', '.jpeg', '.gif', '.bmp'],
        'audio': ['.wav', '.mp3', '.flac', '.aac'],
        'video': ['.mp4', '.avi', '.mkv', '.mov'],
        'document': ['.pdf', '.doc', '.docx']
    }

    @staticmethod
    def get_file_type(filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        for file_type, extensions in FileUtils.SUPPORTED_FORMATS.items():
            if ext in extensions:
                return file_type

        return 'binary'

    @staticmethod
    def is_supported_format(filename: str) -> bool:
        return FileUtils.get_file_type(filename) != 'binary'

    @staticmethod
    def calculate_file_hash(filepath: str) -> str:
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

class Logger:
    _advanced_logger = None
    
    @staticmethod
    def _get_logger():
        if Logger._advanced_logger is None:
            try:
                from shared.advanced_logger import advanced_logger
                Logger._advanced_logger = advanced_logger
            except:
                Logger._advanced_logger = None
        return Logger._advanced_logger
    
    @staticmethod
    def log(level: str, message: str, component: str = "SYSTEM"):
        logger = Logger._get_logger()
        if logger:
            if level == "INFO":
                logger.info(message, component)
            elif level == "ERROR":
                logger.error(message, component)
            elif level == "WARNING":
                logger.warning(message, component)
            elif level == "DEBUG":
                logger.debug(message, component)
        else:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] [{component}] {message}")

    @staticmethod
    def info(message: str, component: str = "SYSTEM"):
        Logger.log("INFO", message, component)

    @staticmethod
    def error(message: str, component: str = "SYSTEM"):
        Logger.log("ERROR", message, component)

    @staticmethod
    def warning(message: str, component: str = "SYSTEM"):
        Logger.log("WARNING", message, component)

    @staticmethod
    def debug(message: str, component: str = "SYSTEM"):
        Logger.log("DEBUG", message, component)
