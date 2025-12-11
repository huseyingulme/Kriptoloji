"""
Affine Cipher - Klasik Doğrusal Şifreleme Algoritması

Affine şifreleme, her harfi (ax + b) mod 26 formülü ile şifreler.
Burada:
- a: Anahtar çarpanı (1 ile 25 arası, 26 ile aralarında asal olmalı)
- b: Anahtar kaydırma (0 ile 25 arası)
- x: Orijinal harf pozisyonu (0-25)

Bu algoritma sadece metin şifreleme için kullanılır.
"""

from algorithms.BaseCipher import BaseCipher


class AffineCipher(BaseCipher):
    """
    Affine Cipher algoritması implementasyonu.
    
    Özellikler:
    - Anahtar formatı: "a,b" (örn: "5,8" - a=5, b=8)
    - a değeri 26 ile aralarında asal olmalı (gcd(a, 26) = 1)
    - Sadece harfleri şifreler (A-Z, a-z)
    - Diğer karakterler (rakam, noktalama vb.) değişmez
    """

    def __init__(self):
        """Affine Cipher'ı başlatır."""
        super().__init__()
        self.name = "Affine Cipher"
        self.description = "Klasik Affine şifreleme algoritması - Her harfi (ax + b) mod 26 formülü ile şifreler"
        self.key_type = "string"
        self.min_key_length = 3  # "a,b" formatı için minimum
        self.max_key_length = 10
        self.key_description = "Anahtar formatı: 'a,b' (örn: '5,8'). a: 1-25 arası, 26 ile aralarında asal. b: 0-25 arası"

    def _gcd(self, a: int, b: int) -> int:
        """Euclidean algoritması ile en büyük ortak bölen (GCD) hesaplar."""
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Modüler ters hesaplar (a^-1 mod m).
        
        Extended Euclidean algoritması kullanır.
        """
        if self._gcd(a, m) != 1:
            return None
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            return None
        
        return (x % m + m) % m

    def _parse_key(self, key: str) -> tuple:
        """
        Anahtarı parse eder.
        
        Format: "a,b" (örn: "5,8")
        
        Args:
            key: Anahtar string'i
            
        Returns:
            tuple: (a, b) değerleri
            
        Raises:
            ValueError: Geçersiz anahtar formatı
        """
        try:
            parts = key.split(',')
            if len(parts) != 2:
                raise ValueError("Anahtar formatı: 'a,b' (örn: '5,8')")
            
            a = int(parts[0].strip())
            b = int(parts[1].strip())
            
            # a kontrolü: 1-25 arası ve 26 ile aralarında asal olmalı
            if a < 1 or a > 25:
                raise ValueError("a değeri 1 ile 25 arasında olmalı")
            
            if self._gcd(a, 26) != 1:
                raise ValueError(f"a={a} değeri 26 ile aralarında asal değil (gcd({a}, 26) != 1)")
            
            # b kontrolü: 0-25 arası
            if b < 0 or b > 25:
                raise ValueError("b değeri 0 ile 25 arasında olmalı")
            
            return a, b
            
        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar: {str(e)}")
        except Exception as e:
            raise ValueError(f"Anahtar parse hatası: {str(e)}")

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi şifreler.
        
        İşlem Adımları:
        1. Anahtarı parse eder (a, b)
        2. Her byte'ı kontrol eder
        3. Harf ise (ax + b) mod 26 formülünü uygular
        4. Değilse olduğu gibi bırakır
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Anahtar string'i ("a,b" formatında)
            
        Returns:
            bytes: Şifrelenmiş veri
        """
        try:
            a, b = self._parse_key(key)
            result = bytearray()

            # Her byte'ı işle
            for byte in data:
                # Büyük harf (A-Z: 65-90)
                if 65 <= byte <= 90:
                    # x = byte - 65 (0-25 arası)
                    x = byte - 65
                    # (ax + b) mod 26
                    encrypted_x = (a * x + b) % 26
                    # Yeni harf: encrypted_x + 65
                    result.append(encrypted_x + 65)
                # Küçük harf (a-z: 97-122)
                elif 97 <= byte <= 122:
                    # x = byte - 97 (0-25 arası)
                    x = byte - 97
                    # (ax + b) mod 26
                    encrypted_x = (a * x + b) % 26
                    # Yeni harf: encrypted_x + 97
                    result.append(encrypted_x + 97)
                else:
                    # Harf değilse olduğu gibi bırak
                    result.append(byte)

            return bytes(result)

        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Şifrelenmiş veriyi çözer.
        
        İşlem Adımları:
        1. Anahtarı parse eder (a, b)
        2. a'nın modüler tersini hesaplar (a^-1 mod 26)
        3. Her byte'ı kontrol eder
        4. Harf ise a^-1(y - b) mod 26 formülünü uygular
        5. Değilse olduğu gibi bırakır
        
        Not: Çözme formülü: x = a^-1(y - b) mod 26
        
        Args:
            data: Çözülecek veri (bytes)
            key: Anahtar string'i ("a,b" formatında)
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            a, b = self._parse_key(key)
            
            # a'nın modüler tersini hesapla
            a_inv = self._mod_inverse(a, 26)
            if a_inv is None:
                raise ValueError(f"a={a} değerinin modüler tersi hesaplanamıyor")
            
            result = bytearray()

            # Her byte'ı işle
            for byte in data:
                # Büyük harf (A-Z: 65-90)
                if 65 <= byte <= 90:
                    # y = byte - 65 (0-25 arası)
                    y = byte - 65
                    # a^-1(y - b) mod 26
                    decrypted_x = (a_inv * (y - b)) % 26
                    # Negatif değerleri düzelt
                    if decrypted_x < 0:
                        decrypted_x += 26
                    # Yeni harf: decrypted_x + 65
                    result.append(decrypted_x + 65)
                # Küçük harf (a-z: 97-122)
                elif 97 <= byte <= 122:
                    # y = byte - 97 (0-25 arası)
                    y = byte - 97
                    # a^-1(y - b) mod 26
                    decrypted_x = (a_inv * (y - b)) % 26
                    # Negatif değerleri düzelt
                    if decrypted_x < 0:
                        decrypted_x += 26
                    # Yeni harf: decrypted_x + 97
                    result.append(decrypted_x + 97)
                else:
                    # Harf değilse olduğu gibi bırak
                    result.append(byte)

            return bytes(result)

        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """
        Anahtarın geçerli olup olmadığını kontrol eder.
        
        Args:
            key: Kontrol edilecek anahtar
            
        Returns:
            bool: Anahtar geçerliyse True
        """
        try:
            self._parse_key(key)
            return True
        except (ValueError, Exception):
            return False

