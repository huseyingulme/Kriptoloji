import re
from algorithms.BaseCipher import BaseCipher


class PlayfairCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Playfair Cipher"
        self.supports_binary = False
        self.description = "5x5 matris tabanlı çift harf şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 25
        self.key_description = "Anahtar kelime (J harfi kullanılmaz, I ile birleştirilir)"
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def _clean_text(self, text: str) -> str:
        text = text.upper().replace("J", "I")
        text = re.sub(r'[^A-Z]', '', text)
        return text

    def _create_matrix(self, key: str) -> list:
        key = self._clean_text(key)
        if not key:
            raise ValueError("Anahtar boş olamaz")

        used = set()
        matrix = []

        # Anahtarı ekle
        for c in key:
            if c not in used and c in self.alphabet:
                used.add(c)
                matrix.append(c)

        # Geri kalan harfleri ekle
        for c in self.alphabet:
            if c not in used:
                used.add(c)
                matrix.append(c)

        # 5x5 matrise çevir
        return [matrix[i:i+5] for i in range(0, 25, 5)]


    def _prepare_pairs(self, text: str) -> list:
        pairs = []
        i = 0

        while i < len(text):
            a = text[i]
            b = ''

            if i + 1 < len(text):
                b = text[i + 1]

                if a == b:      # Aynı harf olması yasak → X ekle
                    pairs.append(a + 'X')
                    i += 1
                else:
                    pairs.append(a + b)
                    i += 2
            else:
                pairs.append(a + 'X')  # Tek harf kalırsa → X ekle
                i += 1

        return pairs

    def _find(self, ch: str, matrix: list):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == ch:
                    return i, j
        return None

    def _encrypt_pair(self, a: str, b: str, m: list) -> str:
        r1, c1 = self._find(a, m)
        r2, c2 = self._find(b, m)

        if r1 == r2:  # same row → shift right
            return m[r1][(c1 + 1) % 5] + m[r2][(c2 + 1) % 5]

        if c1 == c2:  # same column → shift down
            return m[(r1 + 1) % 5][c1] + m[(r2 + 1) % 5][c2]

        # rectangle rule
        return m[r1][c2] + m[r2][c1]

    def _decrypt_pair(self, a: str, b: str, m: list) -> str:
        r1, c1 = self._find(a, m)
        r2, c2 = self._find(b, m)

        if r1 == r2:  # same row → shift left
            return m[r1][(c1 - 1) % 5] + m[r2][(c2 - 1) % 5]

        if c1 == c2:  # same column → shift up
            return m[(r1 - 1) % 5][c1] + m[(r2 - 1) % 5][c2]

        # rectangle rule
        return m[r1][c2] + m[r2][c1]

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = self._clean_text(data.decode("utf-8", errors="ignore"))

            if not text:
                # Eğer hiç harf yoksa (örn binary dosya), olduğu gibi döndür (veya hata ver ama çökme)
                Logger.warning("Playfair: Şifrelenecek alfabetik karakter bulunamadı.", "PlayfairCipher")
                return data

            matrix = self._create_matrix(key)
            pairs = self._prepare_pairs(text)

            cipher = ""
            for p in pairs:
                cipher += self._encrypt_pair(p[0], p[1], matrix)

            return cipher.encode("utf-8")

        except Exception as e:
            from shared.utils import Logger
            Logger.error(f"Playfair hatası: {str(e)}", "PlayfairCipher")
            raise e

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = self._clean_text(data.decode("utf-8", errors="ignore"))

            if len(text) % 2 != 0:
                raise ValueError("Şifreli metin çift sayıda karakter içermeli")

            matrix = self._create_matrix(key)

            pairs = [text[i:i+2] for i in range(0, len(text), 2)]

            plain = ""
            for p in pairs:
                plain += self._decrypt_pair(p[0], p[1], matrix)

            # Gereksiz X pad’leri silme (bazı X’ler gerçek olabilir!)
            if plain.endswith("X"):
                plain = plain[:-1]

            return plain.encode("utf-8")

        except Exception as e:
            raise Exception(f"Playfair çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        if not key:
            return False

        key = self._clean_text(key)

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
