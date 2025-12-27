from algorithms.BaseCipher import BaseCipher


class RailFenceCipher(BaseCipher):
    """
    Rail Fence (Tren) Cipher
    Yer değiştirme (transposition) tabanlı klasik şifreleme algoritması.
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

    # ==================================================
    # KEY
    # ==================================================

    def validate_key(self, key: str) -> bool:
        try:
            rails = int(key)
            return self.min_key_length <= rails <= self.max_key_length
        except Exception:
            return False

    # ==================================================
    # ENCRYPT
    # ==================================================

    def encrypt(self, data: bytes, key: str) -> bytes:
        rails = int(key)
        text = data.decode("utf-8", errors="ignore")

        if rails < 2 or not text:
            return data

        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1  # aşağı +1, yukarı -1

        for char in text:
            fence[rail].append(char)
            rail += direction

            if rail == 0 or rail == rails - 1:
                direction *= -1

        encrypted = "".join("".join(row) for row in fence)
        return encrypted.encode("utf-8")

    # ==================================================
    # DECRYPT
    # ==================================================

    def decrypt(self, data: bytes, key: str) -> bytes:
        rails = int(key)
        text = data.decode("utf-8", errors="ignore")

        if rails < 2 or not text:
            return data

        # 1️⃣ Zigzag yolunu işaretle
        pattern = [[] for _ in range(rails)]
        rail = 0
        direction = 1

        for _ in text:
            pattern[rail].append("*")
            rail += direction

            if rail == 0 or rail == rails - 1:
                direction *= -1

        # 2️⃣ Şifreli metni raylara paylaştır
        index = 0
        for r in range(rails):
            length = len(pattern[r])
            pattern[r] = list(text[index:index + length])
            index += length

        # 3️⃣ Zigzag sırasına göre geri oku
        result = []
        rail = 0
        direction = 1

        for _ in text:
            result.append(pattern[rail].pop(0))
            rail += direction

            if rail == 0 or rail == rails - 1:
                direction *= -1

        return "".join(result).encode("utf-8")
