"""
Caesar Cipher - Klasik Kaydırma Şifreleme Algoritması

Bu algoritma, harfleri alfabe içerisinde belirli bir kaydırma miktarına göre şifreler.
Örnek: Shift = 3 -> 'A' -> 'D', 'X' -> 'A'
"""

from algorithms.BaseCipher import BaseCipher


class CaesarCipher(BaseCipher):
    """
    Caesar Cipher algoritmasının temiz ve optimize implementasyonu.

    Özellikler:
    - Anahtar: 1–999 arası sayı (shift değeri)
    - Yalnızca harfler (A-Z, a-z) kaydırılır
    - Rakamlar, boşluklar ve noktalama işaretleri olduğu gibi kalır
    """
    supports_binary = False

    def __init__(self):
        super().__init__()
        self.name = "Caesar Cipher"
        self.supports_binary = False
        self.description = "Her harfi belirtilen miktarda kaydıran klasik şifreleme algoritması"
        self.key_type = "integer"
        self.min_key_length = 1
        self.max_key_length = 3
        self.key_description = "1 ile 999 arasında kaydırma değeri"


    def encrypt(self, data: bytes, key: str) -> bytes:
        shift = self._convert_key(key)
        result = bytearray()

        for byte in data:
            # Büyük harf: A–Z (65–90)
            if 65 <= byte <= 90:
                new_char = (byte - 65 + shift) % 26 + 65
                result.append(new_char)

            # Küçük harf: a–z (97–122)
            elif 97 <= byte <= 122:
                new_char = (byte - 97 + shift) % 26 + 97
                result.append(new_char)

            # Harf değilse değiştirme
            else:
                result.append(byte)

        return bytes(result)
    def decrypt(self, data: bytes, key: str) -> bytes:
        if not data:
            return b""

        shift = self._convert_key(key)
        # Ters kaydırma: decrypt için shift'in tersini uygula
        reverse_shift = (26 - shift) % 26
        result = bytearray()

        for byte in data:
            if 65 <= byte <= 90:  # A–Z
                # Ters kaydırma uygula: (byte - 65 + reverse_shift) % 26 + 65
                new_char = (byte - 65 + reverse_shift) % 26 + 65
                result.append(new_char)

            elif 97 <= byte <= 122:  # a–z
                # Ters kaydırma uygula: (byte - 97 + reverse_shift) % 26 + 97
                new_char = (byte - 97 + reverse_shift) % 26 + 97
                result.append(new_char)

            else:
                # Harf değilse değiştirme
                result.append(byte)

        return bytes(result)


    def validate_key(self, key: str) -> bool:

        try:
            value = int(key)
            return 1 <= value <= 999
        except Exception:
            return False

    def _convert_key(self, key: str) -> int:


        if not self.validate_key(key):
            raise ValueError("Anahtar geçersiz: 1–999 arasında bir sayı olmalı.")

        return int(key) % 26
