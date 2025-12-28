from algorithms.BaseCipher import BaseCipher
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
import os
import hashlib
import warnings

class IDEACipher(BaseCipher):
    """

    IDEA Özellikleri:
    - Blok Boyutu: 64 bit (8 byte)
    - Anahtar Boyutu: 128 bit (16 byte)
    - Tur Sayısı: 8.5 tur
    """
    
    # Desteklenen IDEA çalışma modları
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB']
    
    # IDEA'nın blok boyutu (64 bit) ve anahtar boyutu (16 byte)
    IDEA_BLOCK_SIZE = 8
    IDEA_KEY_SIZE = 16
    DEFAULT_MODE = 'CBC'

    def __init__(self):
        super().__init__()
        self.name = "IDEA Cipher (Library)"
        self.description = "International Data Encryption Algorithm (Kütüphane tabanlı)"
        self.key_type = "string"
        self.min_key_length = 1 
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'mode:key' (örn: 'CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB."
        self.supports_binary = True

    def _parse_key_string(self, key_string: str) -> Tuple[str, str]:
        """Anahtar dizesini mod ve key string olarak ayrıştırır."""
        parts = key_string.split(':')

        if len(parts) == 1:
            mode = self.DEFAULT_MODE
            key_str = parts[0]
        elif len(parts) == 2:
            mode = parts[0].upper()
            key_str = parts[1]
        elif len(parts) == 3:
            # "IDEA:CBC:key" formatını destekle
            if parts[0].upper() == "IDEA":
                mode = parts[1].upper()
                key_str = parts[2]
            else:
                raise ValueError("Geçersiz IDEA anahtar formatı. 'key' veya 'mode:key' veya 'IDEA:mode:key' kullanın.")
        else:
            raise ValueError("Geçersiz anahtar formatı. 'key' veya 'mode:key' kullanın.")

        if mode not in self.SUPPORTED_MODES:
            raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenenler: {self.SUPPORTED_MODES}")

        return (mode, key_str)

    def _derive_key(self, key_string: str) -> bytes:
        """SHA-256 ile anahtarı 16 byte'a (128-bit) türetir."""
        if not key_string:
            raise ValueError("Anahtar boş olamaz.")
        
        key_hash = hashlib.sha256(key_string.encode()).digest()
        return key_hash[:self.IDEA_KEY_SIZE] 

    def _get_mode_object(self, mode_name: str, iv: bytes = None):
        """Mod objesini döndürür."""
        if mode_name == 'ECB':
            return modes.ECB()
        
        if iv is None:
            raise ValueError(f"{mode_name} modu için IV ({self.IDEA_BLOCK_SIZE} byte) gerekli")

        if mode_name == 'CBC':
            return modes.CBC(iv)
        elif mode_name == 'CFB':
            return modes.CFB(iv)
        elif mode_name == 'OFB':
            return modes.OFB(iv)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")

    def encrypt(self, data: bytes, key: str) -> bytes:
        """IDEA ile veriyi şifreler."""
        try:
            mode_name, key_string = self._parse_key_string(key)
            idea_key = self._derive_key(key_string)
            
            iv = None
            if mode_name != 'ECB':
                iv = os.urandom(self.IDEA_BLOCK_SIZE)
            
            mode = self._get_mode_object(mode_name, iv)
            algorithm = algorithms.IDEA(idea_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()

            # Padding
            if mode_name in ['ECB', 'CBC']:
                padder = padding.PKCS7(self.IDEA_BLOCK_SIZE * 8).padder()
                padded_data = padder.update(data) + padder.finalize()
            else:
                padded_data = data

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext if iv else ciphertext

        except Exception as e:
            raise Exception(f"IDEA şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """IDEA ile şifrelenmiş veriyi çözer."""
        try:
            mode_name, key_string = self._parse_key_string(key)
            idea_key = self._derive_key(key_string)
            
            iv = None
            encrypted_data = data
            if mode_name != 'ECB':
                iv_length = self.IDEA_BLOCK_SIZE
                if len(data) < iv_length:
                    raise ValueError(f"{mode_name}: Eksik IV bilgisi.")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]
            
            mode = self._get_mode_object(mode_name, iv)
            algorithm = algorithms.IDEA(idea_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(self.IDEA_BLOCK_SIZE * 8).unpadder()
                result = unpadder.update(decrypted_data) + unpadder.finalize()
            else:
                result = decrypted_data

            return result

        except Exception as e:
            raise Exception(f"IDEA çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtar formatını doğrular."""
        try:
            self._parse_key_string(key)
            return True
        except:
            return False
