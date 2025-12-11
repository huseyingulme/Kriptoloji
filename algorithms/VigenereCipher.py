from algorithms.BaseCipher import BaseCipher
from typing import Union

class VigenereCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Vigenère Cipher"
        self.description = "Vigenère şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 50
        self.key_description = "Alfabetik karakterler (A-Z, a-z)"

    def encrypt(self, data: bytes, key: str) -> bytes:

        try:
            clean_key = ''.join(c.upper() for c in key if c.isalpha())
            if not clean_key:
                raise ValueError("Anahtar en az bir harf içermeli")

            result = bytearray()
            key_index = 0

            for byte in data:
                if 65 <= byte <= 90:
                    shift = ord(clean_key[key_index % len(clean_key)]) - 65
                    result.append((byte - 65 + shift) % 26 + 65)
                    key_index += 1
                elif 97 <= byte <= 122:
                    shift = ord(clean_key[key_index % len(clean_key)]) - 65
                    result.append((byte - 97 + shift) % 26 + 97)
                    key_index += 1
                else:
                    result.append(byte)

            return bytes(result)

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:

        try:
            clean_key = ''.join(c.upper() for c in key if c.isalpha())
            if not clean_key:
                raise ValueError("Anahtar en az bir harf içermeli")

            result = bytearray()
            key_index = 0

            for byte in data:
                if 65 <= byte <= 90:
                    shift = ord(clean_key[key_index % len(clean_key)]) - 65
                    result.append((byte - 65 - shift) % 26 + 65)
                    key_index += 1
                elif 97 <= byte <= 122:
                    shift = ord(clean_key[key_index % len(clean_key)]) - 65
                    result.append((byte - 97 - shift) % 26 + 97)
                    key_index += 1
                else:
                    result.append(byte)

            return bytes(result)

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:

        if not key:
            return False

        if not any(c.isalpha() for c in key):
            return False

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
