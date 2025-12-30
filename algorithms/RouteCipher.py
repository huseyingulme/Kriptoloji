from algorithms.BaseCipher import BaseCipher
import math


class RouteCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Route Cipher"
        self.supports_binary = False
        self.description = "Matris ve rota tabanlı klasik şifreleme"
        self.key_type = "string"
        self.min_key_length = 3
        self.max_key_length = 30
        self.key_description = (
            "Format: rows:cols:route → Örnek: 3:3:spiral | 4:4:column | 3:3:diagonal"
        )
        self.padding_char = "X"

    def validate_key(self, key: str) -> bool:
        try:
            rows, cols, route = self._parse_key(key)
            return True
        except Exception:
            return False

    def _parse_key(self, key: str):
        parts = key.split(":")
        if len(parts) != 3:
            raise ValueError("Anahtar formatı rows:cols:route olmalıdır.")

        try:
            rows = int(parts[0])
            cols = int(parts[1])
        except ValueError:
            raise ValueError("Satır ve sütun sayı olmalıdır.")

        route = parts[2].lower()

        if rows < 1 or cols < 1:
            raise ValueError("Satır ve sütun en az 1 olmalıdır.")

        if route not in ("spiral", "column", "diagonal"):
            raise ValueError("Rota spiral, column veya diagonal olabilir.")

        return rows, cols, route

    def _get_matrix(self, text, rows, cols):
        """Metni satır satır matrise doldurur."""
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        for i in range(rows * cols):
            r, c = divmod(i, cols)
            if i < len(text):
                matrix[r][c] = text[i]
            else:
                matrix[r][c] = self.padding_char
        return matrix

    def _read_spiral(self, matrix, rows, cols):
        res = []
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1

        while top <= bottom and left <= right:
            # Üst satır (soldan sağa)
            for c in range(left, right + 1):
                res.append(matrix[top][c])
            top += 1

            # Sağ sütun (yukardan aşağı)
            if top <= bottom:
                for r in range(top, bottom + 1):
                    res.append(matrix[r][right])
                right -= 1

            # Alt satır (sağdan sola)
            if top <= bottom and left <= right:
                for c in range(right, left - 1, -1):
                    res.append(matrix[bottom][c])
                bottom -= 1

            # Sol sütun (aşağıdan yukarı)
            if left <= right and top <= bottom:
                for r in range(bottom, top - 1, -1):
                    res.append(matrix[r][left])
                left += 1

        return "".join(res)

    def _read_column(self, matrix, rows, cols):
        return "".join(matrix[r][c] for c in range(cols) for r in range(rows))

    def _read_diagonal(self, matrix, rows, cols):
        res = []
        # d = r + c (top-left to bottom-right diagonals)
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = d - r
                if 0 <= c < cols:
                    res.append(matrix[r][c])
        return "".join(res)

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            rows, cols, route = self._parse_key(key)
            text = data.decode("utf-8", errors="ignore")
        except Exception as e:
            return data

        if not text:
            return data

        # Matrise doldur (Padding otomatik)
        matrix = self._get_matrix(text, rows, cols)

        # Rotaya göre oku
        if route == "spiral":
            cipher_text = self._read_spiral(matrix, rows, cols)
        elif route == "column":
            cipher_text = self._read_column(matrix, rows, cols)
        else: # diagonal
            cipher_text = self._read_diagonal(matrix, rows, cols)

        return cipher_text.encode("utf-8")

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            rows, cols, route = self._parse_key(key)
            cipher_text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data

        if not cipher_text or len(cipher_text) != rows * cols:
            # Eğer boyut uyuşmuyorsa, düzgün çözülemez
            return data

        # 1. Adım: Boş matrisi rotaya göre doldurup yerleri belirle
        matrix = [[0 for _ in range(cols)] for _ in range(rows)]
        
        # Rota sırasına göre hücre koordinatlarını al
        coords = []
        if route == "spiral":
            top, bottom = 0, rows - 1
            left, right = 0, cols - 1
            while top <= bottom and left <= right:
                for c in range(left, right + 1): coords.append((top, c))
                top += 1
                if top <= bottom:
                    for r in range(top, bottom + 1): coords.append((r, right))
                    right -= 1
                if top <= bottom and left <= right:
                    for c in range(right, left - 1, -1): coords.append((bottom, c))
                    bottom -= 1
                if left <= right and top <= bottom:
                    for r in range(bottom, top - 1, -1): coords.append((r, left))
                    left += 1
        elif route == "column":
            for c in range(cols):
                for r in range(rows):
                    coords.append((r, c))
        else: # diagonal
            for d in range(rows + cols - 1):
                for r in range(rows):
                    c = d - r
                    if 0 <= c < cols:
                        coords.append((r, c))

        # 2. Adım: Harfleri rota sırasına göre matrise yerleştir
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        for i, (r, c) in enumerate(coords):
            if i < len(cipher_text):
                matrix[r][c] = cipher_text[i]

        # 3. Adım: Matrisi satır satır oku
        plain_text = "".join(matrix[r][c] for r in range(rows) for c in range(cols))
        
        # Padding temizle (Opsiyonel, ama genellikle sonda 'X'ler kalır)
        return plain_text.encode("utf-8")
