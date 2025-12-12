import re
from algorithms.BaseCipher import BaseCipher


class PolybiusCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Polybius Cipher"
        self.description = "5x5 Polybius karesi ile satır-sütun konum şifreleme"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 25
        self.key_description = "İsteğe bağlı tablo anahtarı (J harfi I ile birleştirilir)"

        # Standart Polybius karesi
        self.default_table = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'K'],
            ['L', 'M', 'N', 'O', 'P'],
            ['Q', 'R', 'S', 'T', 'U'],
            ['V', 'W', 'X', 'Y', 'Z']
        ]

        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J hariç

    # ----------------------------------------------------------
    # ---------------- TEXT CLEAN ------------------------------
    # ----------------------------------------------------------
    def _clean_text(self, text: str) -> str:
        text = text.upper().replace("J", "I")
        text = re.sub(r"[^A-Z]", "", text)
        return text

    # ----------------------------------------------------------
    # ---------------- CREATE TABLE ----------------------------
    # ----------------------------------------------------------
    def _create_table(self, key: str) -> list:
        if not key:
            return self.default_table

        key = self._clean_text(key)

        used = set()
        letters = []

        # Anahtar harflerini ekle
        for c in key:
            if c not in used and c in self.alphabet:
                used.add(c)
                letters.append(c)

        # Kalan harfleri ekle
        for c in self.alphabet:
            if c not in used:
                used.add(c)
                letters.append(c)

        # 5x5 tabloyu oluştur
        return [letters[i:i+5] for i in range(0, 25, 5)]

    # ----------------------------------------------------------
    # ---------------- FIND POSITION ---------------------------
    # ----------------------------------------------------------
    def _find_position(self, char: str, table: list) -> tuple:
        for r in range(5):
            for c in range(5):
                if table[r][c] == char:
                    return r, c
        return None

    # ----------------------------------------------------------
    # -------------------- ENCRYPT -----------------------------
    # ----------------------------------------------------------
    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = self._clean_text(data.decode("utf-8", errors="ignore"))

            if not text:
                raise ValueError("Şifrelenecek geçerli metin yok")

            table = self._create_table(key)

            cipher = ""
            for ch in text:
                pos = self._find_position(ch, table)
                if not pos:
                    raise ValueError(f"Tabloda bulunamayan karakter: {ch}")

                r, c = pos
                cipher += f"{r+1}{c+1}"  # 1–5 indeksleme

            return cipher.encode("utf-8")

        except Exception as e:
            raise Exception(f"Polybius şifreleme hatası: {str(e)}")

    # ----------------------------------------------------------
    # -------------------- DECRYPT -----------------------------
    # ----------------------------------------------------------
    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode("utf-8", errors="ignore")
            text = re.sub(r"[^0-9]", "", text)

            if len(text) == 0:
                raise ValueError("Çözülecek geçerli sayı verisi yok")

            if len(text) % 2 != 0:
                raise ValueError("Polybius şifresi çift haneli olmalıdır (ör: 11 23 45)")

            table = self._create_table(key)

            plain = ""
            for i in range(0, len(text), 2):
                r = int(text[i]) - 1
                c = int(text[i+1]) - 1

                if 0 <= r < 5 and 0 <= c < 5:
                    plain += table[r][c]
                else:
                    plain += "?"  # geçersiz koordinat

            return plain.encode("utf-8")

        except Exception as e:
            raise Exception(f"Polybius çözme hatası: {str(e)}")

    # ----------------------------------------------------------
    # ------------------ VALIDATE KEY --------------------------
    # ----------------------------------------------------------
    def validate_key(self, key: str) -> bool:
        if not key:
            return True

        key = self._clean_text(key)

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
