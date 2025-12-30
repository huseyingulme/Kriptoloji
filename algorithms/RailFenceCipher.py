from algorithms.BaseCipher import BaseCipher


class RailFenceCipher(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Transposition Cipher
    A form of transposition cipher that derives its name from the way in which it is encoded.
    It rearranges the message characters in a zigzag pattern across multiple "rails".

    🔑 [Key Management]
    - The key is the number of "rails" (rows) used to write the message.

    🧮 [Mathematical Foundation]
    - Transposition-based method.
    - Rearranges character positions according to a periodic geometric pattern.
    - Period is 2 * (rails - 1).
    """

    def __init__(self):
        super().__init__()
        self.name = "Rail Fence Cipher"
        self.description = "Zigzag (tren yolu) mantığıyla çalışan yer değiştirme şifrelemesi"
        self.key_type = "integer"
        self.min_key_length = 2
        self.max_key_length = 20
        self.key_description = "Ray sayısı (örn: 3)"
        self.supports_binary = False

    def validate_key(self, key: str) -> bool:
        try:
            rails = int(key)
            return self.min_key_length <= rails <= self.max_key_length
        except Exception:
            return False

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Rail Fence şifreleme işlemi.
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Ray sayısı (str)
        Returns:
            bytes: Şifrelenmiş veri
        """
        try:
            rails = int(key)
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data

        if rails < 2 or not text:
            return data

        # Rayları oluştur
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1  # 1: aşağı, -1: yukarı

        # Zigzag desenine göre harfleri yerleştir
        for char in text:
            fence[rail].append(char)
            
            # Yön değiştirme kontrolü
            if rails > 1:
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1

        # Rayları sırayla birleştir
        encrypted = "".join("".join(row) for row in fence)
        return encrypted.encode("utf-8")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Rail Fence deşifreleme işlemi.
        
        Args:
            data: Şifreli veri (bytes)
            key: Ray sayısı (str)
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            rails = int(key)
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data

        if rails < 2 or not text:
            return data

        # 1. Adım: Zigzag desenindeki boşlukları (markerları) belirle
        pattern = [["" for _ in range(len(text))] for _ in range(rails)]
        rail = 0
        direction = 1

        for i in range(len(text)):
            pattern[rail][i] = "*"
            
            if rails > 1:
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1

        # 2. Adım: Markerların olduğu yerlere şifreli metindeki harfleri yerleştir
        idx = 0
        for r in range(rails):
            for c in range(len(text)):
                if pattern[r][c] == "*" and idx < len(text):
                    pattern[r][c] = text[idx]
                    idx += 1

        # 3. Adım: Zigzag desenine göre matrisi oku
        result = []
        rail = 0
        direction = 1
        for i in range(len(text)):
            result.append(pattern[rail][i])
            
            if rails > 1:
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1

        return "".join(result).encode("utf-8")
