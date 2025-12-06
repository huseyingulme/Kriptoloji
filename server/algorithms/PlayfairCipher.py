import re
from server.algorithms.BaseCipher import BaseCipher

class PlayfairCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Playfair Cipher"
        self.description = "5x5 matris tabanlı çift karakter şifreleme"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 25
        self.key_description = "Anahtar kelime (J hariç 25 harf)"
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore').upper()
            text = re.sub(r'[^A-Z]', '', text)

            if len(text) == 0:
                raise ValueError("Geçerli metin bulunamadı")

            matrix = self._create_matrix(key)
            pairs = self._prepare_pairs(text)

            result = ""
            for pair in pairs:
                encrypted_pair = self._encrypt_pair(pair, matrix)
                result += encrypted_pair

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore').upper()
            text = re.sub(r'[^A-Z]', '', text)

            if len(text) == 0:
                raise ValueError("Geçerli metin bulunamadı")

            matrix = self._create_matrix(key)
            pairs = self._prepare_pairs(text)

            result = ""
            for pair in pairs:
                decrypted_pair = self._decrypt_pair(pair, matrix)
                result += decrypted_pair

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def _create_matrix(self, key: str) -> list:
        key = key.upper().replace('J', 'I')
        key = re.sub(r'[^A-Z]', '', key)

        if not key:
            raise ValueError("Geçerli anahtar bulunamadı")

        matrix = []
        used_chars = set()

        for char in key:
            if char not in used_chars and char in self.alphabet:
                matrix.append(char)
                used_chars.add(char)

        for char in self.alphabet:
            if char not in used_chars:
                matrix.append(char)

        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def _prepare_pairs(self, text: str) -> list:
        pairs = []
        i = 0

        while i < len(text):
            if i + 1 < len(text):
                if text[i] == text[i + 1]:
                    pairs.append(text[i] + 'X')
                    i += 1
                else:
                    pairs.append(text[i] + text[i + 1])
                    i += 2
            else:
                pairs.append(text[i] + 'X')
                i += 1

        return pairs

    def _find_position(self, char: str, matrix: list) -> tuple:
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return (i, j)
        return None

    def _encrypt_pair(self, pair: str, matrix: list) -> str:
        char1, char2 = pair[0], pair[1]
        pos1 = self._find_position(char1, matrix)
        pos2 = self._find_position(char2, matrix)

        if not pos1 or not pos2:
            return pair

        row1, col1 = pos1
        row2, col2 = pos2

        if row1 == row2:
            return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]

    def _decrypt_pair(self, pair: str, matrix: list) -> str:
        char1, char2 = pair[0], pair[1]
        pos1 = self._find_position(char1, matrix)
        pos2 = self._find_position(char2, matrix)

        if not pos1 or not pos2:
            return pair

        row1, col1 = pos1
        row2, col2 = pos2

        if row1 == row2:
            result = matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            result = matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            result = matrix[row1][col2] + matrix[row2][col1]

        if result.endswith('X'):
            result = result[:-1]

        return result

    def validate_key(self, key: str) -> bool:
        if not key:
            return False

        key = key.upper().replace('J', 'I')
        key = re.sub(r'[^A-Z]', '', key)

        if len(key) < self.min_key_length or len(key) > self.max_key_length:
            return False

        return True
