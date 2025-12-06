
from server.algorithms.BaseCipher import BaseCipher
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib

class AESCipher(BaseCipher):
    
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM']
    SUPPORTED_KEY_SIZES = [128, 192, 256]
    DEFAULT_KEY_SIZE = 256
    DEFAULT_MODE = 'CBC'
    
    def __init__(self):
        super().__init__()
        self.name = "AES Cipher"
        self.description = "Advanced Encryption Standard - Modern simetrik blok şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 8
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'key_size:mode:key' (örn: '256:CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB, CTR, GCM. Key size: 128, 192, 256"
        self.supports_binary = True
    
    def _parse_key_string(self, key_string: str) -> tuple:
        
        parts = key_string.split(':', 2)
        
        if len(parts) == 1:
            return (self.DEFAULT_KEY_SIZE, self.DEFAULT_MODE, parts[0])
        elif len(parts) == 3:
            try:
                key_size = int(parts[0])
                mode = parts[1].upper()
                key = parts[2]
                
                if key_size not in self.SUPPORTED_KEY_SIZES:
                    raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}. Desteklenen: {self.SUPPORTED_KEY_SIZES}")
                
                if mode not in self.SUPPORTED_MODES:
                    raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")
                
                return (key_size, mode, key)
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'key_size:mode:key'")
                raise
        else:
            raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'key_size:mode:key'")
    
    def _derive_key(self, key_string: str, key_size: int) -> bytes:
        
        salt = hashlib.sha256(key_string.encode()).digest()[:16]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size // 8,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(key_string.encode())
        return key
    
    def _get_mode_object(self, mode_name: str, iv: bytes = None):
        
        if mode_name == 'ECB':
            return modes.ECB()
        elif mode_name == 'CBC':
            if iv is None:
                raise ValueError("CBC modu için IV gerekli")
            return modes.CBC(iv)
        elif mode_name == 'CFB':
            if iv is None:
                raise ValueError("CFB modu için IV gerekli")
            return modes.CFB(iv)
        elif mode_name == 'OFB':
            if iv is None:
                raise ValueError("OFB modu için IV gerekli")
            return modes.OFB(iv)
        elif mode_name == 'CTR':
            if iv is None:
                raise ValueError("CTR modu için IV (nonce) gerekli")
            return modes.CTR(iv)
        elif mode_name == 'GCM':
            if iv is None:
                raise ValueError("GCM modu için IV (nonce) gerekli")
            return modes.GCM(iv)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        
        try:
            key_size, mode_name, key_string = self._parse_key_string(key)
            
            aes_key = self._derive_key(key_string, key_size)
            
            if mode_name == 'ECB':
                iv = None
                mode = self._get_mode_object(mode_name)
            else:
                iv_length = 12 if mode_name == 'GCM' else 16
                iv = os.urandom(iv_length)
                mode = self._get_mode_object(mode_name, iv)
            
            if key_size == 128:
                algorithm = algorithms.AES128(aes_key)
            elif key_size == 192:
                algorithm = algorithms.AES192(aes_key)
            else:
                algorithm = algorithms.AES256(aes_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()
            
            if mode_name in ['ECB', 'CBC', 'CFB', 'OFB']:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
            else:
                padded_data = data
            
            if mode_name == 'GCM':
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                result = iv + ciphertext + encryptor.tag
            else:
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                result = iv + ciphertext if iv else ciphertext
            
            return result
            
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        
        try:
            key_size, mode_name, key_string = self._parse_key_string(key)
            
            aes_key = self._derive_key(key_string, key_size)
            
            if mode_name == 'ECB':
                iv = None
                encrypted_data = data
            elif mode_name == 'GCM':
                iv_length = 12
                tag_length = 16
                if len(data) < iv_length + tag_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                tag = data[-tag_length:]
                encrypted_data = data[iv_length:-tag_length]
            else:
                iv_length = 16
                if len(data) < iv_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]
            
            if mode_name == 'GCM':
                mode = modes.GCM(iv, tag)
            else:
                mode = self._get_mode_object(mode_name, iv) if iv else self._get_mode_object(mode_name)
            
            if key_size == 128:
                algorithm = algorithms.AES128(aes_key)
            elif key_size == 192:
                algorithm = algorithms.AES192(aes_key)
            else:
                algorithm = algorithms.AES256(aes_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()
            
            if mode_name == 'GCM':
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            else:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            if mode_name in ['ECB', 'CBC', 'CFB', 'OFB']:
                unpadder = padding.PKCS7(128).unpadder()
                result = unpadder.update(decrypted_data)
                result += unpadder.finalize()
            else:
                result = decrypted_data
            
            return result
            
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")
    
    def validate_key(self, key: str) -> bool:
        
        try:
            self._parse_key_string(key)
            return True
        except (ValueError, Exception):
            return False

