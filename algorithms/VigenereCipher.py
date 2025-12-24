from algorithms.BaseCipher import BaseCipher
import string

class VigenereCipher(BaseCipher):
    """
    Vigenère Cipher – Çok alfabeli kaydırma şifrelemesi.
    Sadece harfler üzerinde işlem yapar, diğer karakterlere dokunmaz.
    """

    def __init__(self):
        super().__init__()
        self.name = "Vigenère Cipher"
        self.supports_binary = False
        self.description = "Çok alfabeli kaydırma tabanlı klasik şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 50
        self.key_description = "Sadece alfabetik karakterlerden oluşan anahtar (A-Z, a-z)"
        self.supports_binary = False

    def validate_key(self, key: str) -> bool:
        """Anahtar doğrulama."""
        if not key:
            return False
        if not any(c.isalpha() for c in key):
            return False
        return self.min_key_length <= len(key) <= self.max_key_length

    def _prepare_key(self, key: str) -> str:
        """Anahtarı temizler ve büyük harfe çevirir."""
        clean = ''.join(c.upper() for c in key if c.isalpha())
        if not clean:
            raise ValueError("Anahtar sadece harf içermeli.")
        return clean

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            key = self._prepare_key(key)
            result = []
            key_index = 0

            for b in data:
                char = chr(b)

                if char.isupper():  # A-Z
                    shift = ord(key[key_index % len(key)]) - 65
                    enc = (ord(char) - 65 + shift) % 26 + 65
                    result.append(chr(enc))
                    key_index += 1

                elif char.islower():  # a-z
                    shift = ord(key[key_index % len(key)]) - 65
                    enc = (ord(char) - 97 + shift) % 26 + 97
                    result.append(chr(enc))
                    key_index += 1

                else:
                    result.append(char)

            return ''.join(result).encode('utf-8')

        except Exception as e:
            raise Exception(f"Vigenère şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            key = self._prepare_key(key)
            result = []
            key_index = 0

            for b in data:
                char = chr(b)

                if char.isupper():  # A-Z
                    shift = ord(key[key_index % len(key)]) - 65
                    dec = (ord(char) - 65 - shift) % 26 + 65
                    result.append(chr(dec))
                    key_index += 1

                elif char.islower():  # a-z
                    shift = ord(key[key_index % len(key)]) - 65
                    dec = (ord(char) - 97 - shift) % 26 + 97
                    result.append(chr(dec))
                    key_index += 1

                else:
                    result.append(char)

            return ''.join(result).encode('utf-8')

        except Exception as e:
            raise Exception(f"Vigenère çözme hatası: {str(e)}")