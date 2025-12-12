from algorithms.BaseCipher import BaseCipher


class RailFenceCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Rail Fence Cipher"
        self.description = "Zikzak (zigzag) ray dizilimi ile yapılan aktarım şifrelemesi"
        self.key_type = "integer"
        self.min_key_length = 2
        self.max_key_length = 10
        self.key_description = "Ray sayısı (2 ile 10 arasında olmalı)"

    # -----------------------------------------------------
    # ENCRYPT
    # -----------------------------------------------------
    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode("utf-8", errors="ignore")
            rails = int(key)

            if rails < 2:
                raise ValueError("Ray sayısı en az 2 olmalıdır")

            if len(text) == 0:
                return b""

            # Rayları oluştur
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1  # aşağı = +1, yukarı = -1

            for char in text:
                fence[rail].append(char)
                rail += direction

                # uçlara gelince yön değiştir
                if rail == 0 or rail == rails - 1:
                    direction *= -1

            encrypted = "".join("".join(r) for r in fence)
            return encrypted.encode("utf-8")

        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    # -----------------------------------------------------
    # DECRYPT
    # -----------------------------------------------------
    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode("utf-8", errors="ignore")
            rails = int(key)

            if rails < 2:
                raise ValueError("Ray sayısı en az 2 olmalıdır")

            if len(text) == 0:
                return b""

            # 1) Zigzag boyunca her raya düşecek karakter sayısını hesapla
            rail_lengths = [0] * rails
            rail = 0
            direction = 1

            for _ in text:
                rail_lengths[rail] += 1
                rail += direction

                if rail == 0 or rail == rails - 1:
                    direction *= -1

            # 2) Metni raylara böl
            fence = []
            index = 0
            for length in rail_lengths:
                fence.append(list(text[index:index + length]))
                index += length

            # 3) Zigzag sırasına göre karakterleri geri al
            result = ""
            rail = 0
            direction = 1

            for _ in text:
                result += fence[rail].pop(0)
                rail += direction

                if rail == 0 or rail == rails - 1:
                    direction *= -1

            return result.encode("utf-8")

        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    # -----------------------------------------------------
    # KEY VALIDATION
    # -----------------------------------------------------
    def validate_key(self, key: str) -> bool:
        try:
            rails = int(key)
            return self.min_key_length <= rails <= self.max_key_length
        except Exception:
            return False
