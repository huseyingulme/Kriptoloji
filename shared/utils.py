import json
import struct
import hashlib
import os
from typing import Dict, Any, Tuple, List

class DataPacket:

    @staticmethod
    def create_packet(data: bytes, packet_type: str, metadata: Dict[str, Any] = None) -> bytes:
        if metadata is None:
            metadata = {}

        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_size = len(metadata_json)

        packet = struct.pack('!II', len(data), metadata_size)
        packet += metadata_json
        packet += data

        return packet

    @staticmethod
    def parse_packet(packet: bytes) -> Tuple[bytes, str, Dict[str, Any]]:
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
