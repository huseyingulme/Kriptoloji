from server.algorithms.BaseCipher import BaseCipher
from typing import Union

class CaesarCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Caesar Cipher"
        self.description = "Klasik Caesar şifreleme algoritması"
        self.key_type = "integer"
        self.min_key_length = 1
        self.max_key_length = 3
        self.key_description = "1-999 arası sayı"

    def encrypt(self, data: bytes, key: str) -> bytes:

        try:
            shift = int(key) % 26
            result = bytearray()

            for byte in data:
                if 65 <= byte <= 90:
                    result.append((byte - 65 + shift) % 26 + 65)
                elif 97 <= byte <= 122:
                    result.append((byte - 97 + shift) % 26 + 97)
                else:
                    result.append(byte)

            return bytes(result)

        except ValueError:
            raise ValueError("Geçersiz anahtar: sayı olmalı")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:

        try:
            shift = int(key) % 26
            result = bytearray()

            for byte in data:
                if 65 <= byte <= 90:
                    result.append((byte - 65 - shift) % 26 + 65)
                elif 97 <= byte <= 122:
                    result.append((byte - 97 - shift) % 26 + 97)
                else:
                    result.append(byte)

            return bytes(result)

        except ValueError:
            raise ValueError("Geçersiz anahtar: sayı olmalı")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:

        try:
            shift = int(key)
            return 1 <= shift <= 999
        except ValueError:
            return False
