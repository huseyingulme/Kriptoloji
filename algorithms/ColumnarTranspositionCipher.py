from algorithms.BaseCipher import BaseCipher

class ColumnarTranspositionCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Columnar Transposition Cipher"
        self.description = "Sütunlu kaydırma tabanlı aktarım şifrelemesi"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 20
        self.key_description = "Anahtar kelime (sütun sırasını belirler)"

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore').upper()
            key = key.upper()

            if not key:
                raise ValueError("Anahtar boş olamaz")

            if len(text) == 0:
                return b""

            key_order = self._get_key_order(key)
            num_cols = len(key_order)

            while len(text) % num_cols != 0:
                text += 'X'

            matrix = []
            for i in range(0, len(text), num_cols):
                matrix.append(list(text[i:i + num_cols]))

            result = ""
            for col in key_order:
                for row in matrix:
                    if col < len(row):
                        result += row[col]

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore').upper()
            key = key.upper()

            if not key:
                raise ValueError("Anahtar boş olamaz")

            if len(text) == 0:
                return b""

            key_order = self._get_key_order(key)
            num_cols = len(key_order)
            num_rows = len(text) // num_cols

            matrix = [[''] * num_cols for _ in range(num_rows)]

            text_index = 0
            for col in key_order:
                for row in range(num_rows):
                    if text_index < len(text):
                        matrix[row][col] = text[text_index]
                        text_index += 1

            result = ""
            for row in matrix:
                result += ''.join(row)

            while result.endswith('X'):
                result = result[:-1]

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def _get_key_order(self, key: str) -> list:
        key_chars = list(key)
        sorted_key = sorted(key_chars)

        order = []
        used_positions = set()

        for char in sorted_key:
            for i, key_char in enumerate(key_chars):
                if key_char == char and i not in used_positions:
                    order.append(i)
                    used_positions.add(i)
                    break

        return order

    def validate_key(self, key: str) -> bool:
        if not key:
            return False

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
