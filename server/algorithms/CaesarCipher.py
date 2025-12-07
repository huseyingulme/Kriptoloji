"""
Caesar Cipher - Klasik Kaydırma Şifreleme Algoritması

Bu algoritma, her harfi alfabede belirli bir sayı kadar kaydırarak şifreler.
Örnek: Shift=3 ise, 'A' -> 'D', 'B' -> 'E' olur.

Bu algoritma sadece metin şifreleme için kullanılır.
"""

from server.algorithms.BaseCipher import BaseCipher


class CaesarCipher(BaseCipher):
    """
    Caesar Cipher algoritması implementasyonu.
    
    Özellikler:
    - Anahtar: 1-999 arası sayı (shift değeri)
    - Sadece harfleri şifreler (A-Z, a-z)
    - Diğer karakterler (rakam, noktalama vb.) değişmez
    """

    def __init__(self):
        """Caesar Cipher'ı başlatır."""
        super().__init__()
        self.name = "Caesar Cipher"
        self.description = "Klasik Caesar şifreleme algoritması - Her harfi belirli bir sayı kadar kaydırır"
        self.key_type = "integer"
        self.min_key_length = 1
        self.max_key_length = 3  # 999'a kadar
        self.key_description = "1-999 arası sayı (kaydırma miktarı)"

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi şifreler.
        
        İşlem Adımları:
        1. Anahtarı sayıya çevirir
        2. Her byte'ı kontrol eder
        3. Harf ise kaydırır, değilse olduğu gibi bırakır
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Kaydırma miktarı (string olarak sayı)
            
        Returns:
            bytes: Şifrelenmiş veri
        """
        try:
            # Anahtarı sayıya çevir ve mod 26 al (alfabe 26 harf)
            shift = int(key) % 26
            result = bytearray()

            # Her byte'ı işle
            for byte in data:
                # Büyük harf (A-Z: 65-90)
                if 65 <= byte <= 90:
                    # Harfi kaydır: (byte - 65 + shift) % 26 + 65
                    # Örnek: 'A' (65) + shift=3 -> 'D' (68)
                    result.append((byte - 65 + shift) % 26 + 65)
                # Küçük harf (a-z: 97-122)
                elif 97 <= byte <= 122:
                    # Harfi kaydır: (byte - 97 + shift) % 26 + 97
                    # Örnek: 'a' (97) + shift=3 -> 'd' (100)
                    result.append((byte - 97 + shift) % 26 + 97)
                else:
                    # Harf değilse olduğu gibi bırak (rakam, noktalama vb.)
                    result.append(byte)

            return bytes(result)

        except ValueError:
            raise ValueError("Geçersiz anahtar: sayı olmalı")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Şifrelenmiş veriyi çözer.
        
        İşlem Adımları:
        1. Anahtarı sayıya çevirir
        2. Her byte'ı kontrol eder
        3. Harf ise geri kaydırır, değilse olduğu gibi bırakır
        
        Not: Çözme işlemi şifrelemenin tersidir (shift yerine -shift)
        
        Args:
            data: Çözülecek veri (bytes)
            key: Kaydırma miktarı (string olarak sayı)
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            # Anahtarı sayıya çevir ve mod 26 al
            shift = int(key) % 26
            result = bytearray()

            # Her byte'ı işle
            for byte in data:
                # Büyük harf (A-Z: 65-90)
                if 65 <= byte <= 90:
                    # Harfi geri kaydır: (byte - 65 - shift) % 26 + 65
                    # Örnek: 'D' (68) - shift=3 -> 'A' (65)
                    result.append((byte - 65 - shift) % 26 + 65)
                # Küçük harf (a-z: 97-122)
                elif 97 <= byte <= 122:
                    # Harfi geri kaydır: (byte - 97 - shift) % 26 + 97
                    # Örnek: 'd' (100) - shift=3 -> 'a' (97)
                    result.append((byte - 97 - shift) % 26 + 97)
                else:
                    # Harf değilse olduğu gibi bırak
                    result.append(byte)

            return bytes(result)

        except ValueError:
            raise ValueError("Geçersiz anahtar: sayı olmalı")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """
        Anahtarın geçerli olup olmadığını kontrol eder.
        
        Args:
            key: Kontrol edilecek anahtar
            
        Returns:
            bool: Anahtar geçerliyse True (1-999 arası sayı)
        """
        try:
            shift = int(key)
            return 1 <= shift <= 999
        except ValueError:
            return False
