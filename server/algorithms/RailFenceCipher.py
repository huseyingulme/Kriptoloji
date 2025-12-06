from server.algorithms.BaseCipher import BaseCipher

class RailFenceCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Rail Fence Cipher"
        self.description = "Zikzak desen tabanlı aktarım şifrelemesi"
        self.key_type = "integer"
        self.min_key_length = 2
        self.max_key_length = 10
        self.key_description = "Ray sayısı (2-10 arası)"

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore')
            rails = int(key)

            if rails < 2:
                raise ValueError("Ray sayısı en az 2 olmalı")

            if len(text) == 0:
                return b""

            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1

            for char in text:
                fence[rail].append(char)
                rail += direction

                if rail == rails - 1 or rail == 0:
                    direction = -direction

            result = ''.join([''.join(rail) for rail in fence])
            return result.encode('utf-8')

        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore')
            rails = int(key)

            if rails < 2:
                raise ValueError("Ray sayısı en az 2 olmalı")

            if len(text) == 0:
                return b""

            fence = [[] for _ in range(rails)]
            rail_lengths = [0] * rails
            rail = 0
            direction = 1

            for _ in text:
                rail_lengths[rail] += 1
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction

            index = 0
            for i in range(rails):
                fence[i] = list(text[index:index + rail_lengths[i]])
                index += rail_lengths[i]

            result = ""
            rail = 0
            direction = 1

            for _ in text:
                if fence[rail]:
                    result += fence[rail].pop(0)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction

            return result.encode('utf-8')

        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        try:
            rails = int(key)
            return 2 <= rails <= 10
        except ValueError:
            return False
