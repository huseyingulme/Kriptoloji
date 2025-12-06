from server.algorithms.BaseCipher import BaseCipher
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import hashlib

class DESCipher(BaseCipher):

    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB']
    DES_KEY_SIZE = 64
    DEFAULT_MODE = 'CBC'

    def __init__(self):
        super().__init__()
        self.name = "DES Cipher"
        self.description = "Data Encryption Standard - Klasik simetrik blok şifreleme algoritması (64-bit blok, 56-bit efektif anahtar)"
        self.key_type = "string"
        self.min_key_length = 8
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'mode:key' (örn: 'CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB"
        self.supports_binary = True

    def _parse_key_string(self, key_string: str) -> tuple:

        parts = key_string.split(':', 1)

        if len(parts) == 1:
            return (self.DEFAULT_MODE, parts[0])
        elif len(parts) == 2:
            mode = parts[0].upper()
            key = parts[1]

            if mode not in self.SUPPORTED_MODES:
                raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")

            return (mode, key)
        else:
            raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'mode:key'")

    def _derive_key(self, key_string: str) -> bytes:

        key_hash = hashlib.sha256(key_string.encode()).digest()
        des_key = key_hash[:8]
        return des_key

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
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")

    def encrypt(self, data: bytes, key: str) -> bytes:

        try:
            mode_name, key_string = self._parse_key_string(key)

            des_key = self._derive_key(key_string)

            if mode_name == 'ECB':
                iv = None
                mode = self._get_mode_object(mode_name)
            else:
                iv = os.urandom(8)
                mode = self._get_mode_object(mode_name, iv)

            triple_des_key = des_key * 3
            algorithm = algorithms.TripleDES(triple_des_key)

            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()

            if mode_name in ['ECB', 'CBC']:
                padder = padding.PKCS7(64).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
            else:
                padded_data = data

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            result = iv + ciphertext if iv else ciphertext

            return result

        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:

        try:
            mode_name, key_string = self._parse_key_string(key)

            des_key = self._derive_key(key_string)

            if mode_name == 'ECB':
                iv = None
                encrypted_data = data
            else:
                iv_length = 8
                if len(data) < iv_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]

            mode = self._get_mode_object(mode_name, iv) if iv else self._get_mode_object(mode_name)

            triple_des_key = des_key * 3
            algorithm = algorithms.TripleDES(triple_des_key)
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(64).unpadder()
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
