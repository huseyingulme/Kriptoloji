from .base import TextEncryptionAlgorithm
from typing import Union
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import hashlib

class DESCipher(TextEncryptionAlgorithm):

    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB']
    DEFAULT_MODE = 'CBC'

    def __init__(self):
        super().__init__("DES")
        self.required_params = ['key']

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

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:

        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: key")

        key_string = kwargs['key']
        text = data if isinstance(data, str) else data.decode('utf-8')

        try:
            mode_name, key_str = self._parse_key_string(key_string)

            des_key = self._derive_key(key_str)

            text_bytes = text.encode('utf-8')

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
                padded_data = padder.update(text_bytes)
                padded_data += padder.finalize()
            else:
                padded_data = text_bytes

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            result_bytes = iv + ciphertext if iv else ciphertext
            result = base64.b64encode(result_bytes).decode('utf-8')

            return result

        except Exception as e:
            raise ValueError(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:

        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: key")

        key_string = kwargs['key']
        encrypted_text = data if isinstance(data, str) else data.decode('utf-8')

        try:
            mode_name, key_str = self._parse_key_string(key_string)

            des_key = self._derive_key(key_str)

            encrypted_bytes = base64.b64decode(encrypted_text)

            if mode_name == 'ECB':
                iv = None
                ciphertext = encrypted_bytes
            else:
                iv = encrypted_bytes[:8]
                ciphertext = encrypted_bytes[8:]

            mode = self._get_mode_object(mode_name, iv) if iv else self._get_mode_object(mode_name)

            triple_des_key = des_key * 3
            algorithm = algorithms.TripleDES(triple_des_key)
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(64).unpadder()
                result_bytes = unpadder.update(decrypted_data)
                result_bytes += unpadder.finalize()
            else:
                result_bytes = decrypted_data

            result = result_bytes.decode('utf-8')

            return result

        except Exception as e:
            raise ValueError(f"Çözme hatası: {str(e)}")

    def get_info(self):

        info = super().get_info()
        info.update({
            'description': 'Data Encryption Standard - Klasik simetrik blok şifreleme algoritması. Metin tabanlı kullanım için base64 encoding kullanır.',
            'required_params': ['key'],
            'param_descriptions': {
                'key': 'Anahtar formatı: "key" veya "mode:key" (örn: "CBC:my_secret_key"). Modlar: ECB, CBC, CFB, OFB'
            }
        })
        return info
