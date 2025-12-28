"""
Affine Cipher - Klasik Doğrusal Şifreleme Algoritması

Şifreleme formülü:
    E(x) = (a * x + b) mod 26

Çözme formülü:
    D(y) = a_inv * (y - b) mod 26

Koşullar:
- a: 1–25 arası ve gcd(a, 26) = 1 olmalı
- b: 0–25 arası
"""

from algorithms.BaseCipher import BaseCipher


class AffineCipher(BaseCipher):
    """
    Affine Cipher algoritmasının temiz ve optimize implementasyonu.
    """
    supports_binary = False

    def __init__(self):
        super().__init__()
        self.name = "Affine Cipher"
        self.description = "Her harfi (a*x + b) mod 26 formülü ile şifreleyen klasik algoritma"
        self.key_type = "string"
        self.min_key_length = 3
        self.max_key_length = 10
        self.key_description = "Format: 'a,b' — a: 1–25, 26 ile aralarında asal; b: 0–25"

    def _gcd(self, a: int, b: int) -> int:
        """En büyük ortak bölen (Euclid)."""
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Modüler ters (a^-1 mod m).
        Extended Euclidean algoritması kullanılır.
        """

        if self._gcd(a, m) != 1:
            return None

        # Extended Euclidean Algorithm
        def egcd(x, y):
            if x == 0:
                return y, 0, 1
            g, y1, x1 = egcd(y % x, x)
            return g, x1 - (y // x) * y1, y1

        g, inv, _ = egcd(a, m)
        if g != 1:
            return None

        return inv % m



    def _parse_key(self, key: str) -> tuple[int, int]:
        """
        Anahtarı "a,b" formatında parse eder.

        Returns:
            (a, b)
        """

        parts = key.split(',')
        if len(parts) != 2:
            raise ValueError("Anahtar formatı 'a,b' şeklinde olmalı (örn: '5,8')")

        try:
            a = int(parts[0].strip())
            b = int(parts[1].strip())
        except Exception:
            raise ValueError("Anahtar sayısal olmalı. Örn: '5,8'")

        # a doğrulama
        if not (1 <= a <= 25):
            raise ValueError("a değeri 1 ile 25 arasında olmalı")

        if self._gcd(a, 26) != 1:
            raise ValueError("a değeri 26 ile aralarında asal olmalı (gcd(a, 26) = 1)")

        # b doğrulama
        if not (0 <= b <= 25):
            raise ValueError("b değeri 0 ile 25 arasında olmalı")

        return a, b


    def _encrypt_char(self, byte: int, a: int, b: int) -> int:
        """Tek bir karakteri şifreler."""
        if 65 <= byte <= 90:  # A–Z
            x = byte - 65
            return (a * x + b) % 26 + 65

        if 97 <= byte <= 122:  # a–z
            x = byte - 97
            return (a * x + b) % 26 + 97

        return byte  # harf değilse değişme

    def _decrypt_char(self, byte: int, a_inv: int, b: int) -> int:
        """Tek bir karakteri çözer."""
        if 65 <= byte <= 90:  # A–Z
            y = byte - 65
            return ((a_inv * (y - b)) % 26) + 65

        if 97 <= byte <= 122:  # a–z
            y = byte - 97
            return ((a_inv * (y - b)) % 26) + 97

        return byte

    def encrypt(self, data: bytes, key: str) -> bytes:
        a, b = self._parse_key(key)
        result = bytearray()

        for byte in data:
            result.append(self._encrypt_char(byte, a, b))

        return bytes(result)

    def decrypt(self, data: bytes, key: str) -> bytes:
        a, b = self._parse_key(key)
        a_inv = self._mod_inverse(a, 26)

        if a_inv is None:
            raise ValueError(f"{a} için modüler ters hesaplanamadı — gcd(a, 26) = 1 olmalı")

        result = bytearray()

        for byte in data:
            result.append(self._decrypt_char(byte, a_inv, b))

        return bytes(result)


    def validate_key(self, key: str) -> bool:
        try:
            self._parse_key(key)
            return True
        except Exception:
            return False
