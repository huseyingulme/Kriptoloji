import re
from server.algorithms.BaseCipher import BaseCipher

class PolybiusCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Polybius Cipher"
        self.description = "5x5 tablo tabanlı satır/sütun şifrelemesi"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 25
        self.key_description = "Tablo düzeni anahtarı (opsiyonel)"
        self.default_table = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'K'],
            ['L', 'M', 'N', 'O', 'P'],
            ['Q', 'R', 'S', 'T', 'U'],
            ['V', 'W', 'X', 'Y', 'Z']
        ]

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore').upper()
            text = re.sub(r'[^A-Z]', '', text)
            text = text.replace('J', 'I')

            if len(text) == 0:
                raise ValueError("Geçerli metin bulunamadı")

            table = self._create_table(key) if key else self.default_table

            result = ""
            for char in text:
                if char == 'J':
                    char = 'I'

                position = self._find_position(char, table)
                if position:
                    row, col = position
                    result += f"{row + 1}{col + 1}"
                else:
                    result += "00"

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore')
            text = re.sub(r'[^0-9]', '', text)

            if len(text) == 0:
                raise ValueError("Geçerli şifreli metin bulunamadı")

            if len(text) % 2 != 0:
                raise ValueError("Şifreli metin çift uzunlukta olmalı")

            table = self._create_table(key) if key else self.default_table

            result = ""
            for i in range(0, len(text), 2):
                if i + 1 < len(text):
                    row = int(text[i]) - 1
                    col = int(text[i + 1]) - 1

                    if 0 <= row < 5 and 0 <= col < 5:
                        result += table[row][col]
                    else:
                        result += "?"

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def _create_table(self, key: str) -> list:
        key = key.upper().replace('J', 'I')
        key = re.sub(r'[^A-Z]', '', key)

        if not key:
            return self.default_table

        used_chars = set()
        table = []
        current_row = []

        for char in key:
            if char not in used_chars and char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
                current_row.append(char)
                used_chars.add(char)

                if len(current_row) == 5:
                    table.append(current_row)
                    current_row = []

        for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if char not in used_chars:
                current_row.append(char)
                if len(current_row) == 5:
                    table.append(current_row)
                    current_row = []

        if current_row:
            while len(current_row) < 5:
                current_row.append('X')
            table.append(current_row)

        return table

    def _find_position(self, char: str, table: list) -> tuple:
        for i in range(5):
            for j in range(5):
                if table[i][j] == char:
                    return (i, j)
        return None

    def validate_key(self, key: str) -> bool:
        if not key:
            return True

        key = key.upper().replace('J', 'I')
        key = re.sub(r'[^A-Z]', '', key)

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
