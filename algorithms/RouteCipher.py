"""
Route Cipher (Rota Tabanlı Şifreleme)

Plaintext matrise SATIR SATIR yazılır.
Şifreleme: Matris seçilen rotaya göre okunur.
Deşifre: Matris seçilen rotaya göre doldurulur, SATIR SATIR okunur.

Desteklenen rotalar:
- spiral
- column
- diagonal
"""

from algorithms.BaseCipher import BaseCipher


class RouteCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Route Cipher"
        self.supports_binary = False
        self.description = "Matris ve rota tabanlı klasik şifreleme"
        self.key_type = "string"
        self.min_key_length = 3
        self.max_key_length = 20
        self.key_description = (
            "Format: rows:cols:route → Örnek: 3:3:spiral | 4:4:column | 3:3:diagonal"
        )

    # --------------------------------------------------
    # KEY PARSER
    # --------------------------------------------------

    def _parse_key(self, key: str):
        parts = key.split(":")
        if len(parts) != 3:
            raise ValueError("Anahtar formatı rows:cols:route olmalıdır.")

        rows = int(parts[0])
        cols = int(parts[1])
        route = parts[2].lower()

        if rows < 2 or cols < 2:
            raise ValueError("Satır ve sütun en az 2 olmalıdır.")

        if route not in ("spiral", "column", "diagonal"):
            raise ValueError("Rota spiral, column veya diagonal olabilir.")

        return rows, cols, route

    # --------------------------------------------------
    # MATRIX HELPERS
    # --------------------------------------------------

    def _fill_rowwise(self, text, rows, cols):
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for r in range(rows):
            for c in range(cols):
                if idx < len(text):
                    matrix[r][c] = text[idx]
                idx += 1
        return matrix

    def _read_rowwise(self, matrix, rows, cols):
        return "".join(matrix[r][c] for r in range(rows) for c in range(cols))

    # --------------------------------------------------
    # SPIRAL ROUTE
    # --------------------------------------------------

    def _read_spiral(self, matrix, rows, cols):
        res = []
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1

        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                res.append(matrix[top][c])
            top += 1

            for r in range(top, bottom + 1):
                res.append(matrix[r][right])
            right -= 1

            if top <= bottom:
                for c in range(right, left - 1, -1):
                    res.append(matrix[bottom][c])
                bottom -= 1

            if left <= right:
                for r in range(bottom, top - 1, -1):
                    res.append(matrix[r][left])
                left += 1

        return "".join(res)

    def _write_spiral(self, text, rows, cols):
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        idx = 0
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1

        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                matrix[top][c] = text[idx]
                idx += 1
            top += 1

            for r in range(top, bottom + 1):
                matrix[r][right] = text[idx]
                idx += 1
            right -= 1

            if top <= bottom:
                for c in range(right, left - 1, -1):
                    matrix[bottom][c] = text[idx]
                    idx += 1
                bottom -= 1

            if left <= right:
                for r in range(bottom, top - 1, -1):
                    matrix[r][left] = text[idx]
                    idx += 1
                left += 1

        return matrix

    # --------------------------------------------------
    # COLUMN ROUTE
    # --------------------------------------------------

    def _read_column(self, matrix, rows, cols):
        return "".join(matrix[r][c] for c in range(cols) for r in range(rows))

    def _write_column(self, text, rows, cols):
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for c in range(cols):
            for r in range(rows):
                matrix[r][c] = text[idx]
                idx += 1
        return matrix

    # --------------------------------------------------
    # DIAGONAL ROUTE
    # --------------------------------------------------

    def _read_diagonal(self, matrix, rows, cols):
        res = []
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = d - r
                if 0 <= c < cols:
                    res.append(matrix[r][c])
        return "".join(res)

    def _write_diagonal(self, text, rows, cols):
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = d - r
                if 0 <= c < cols:
                    matrix[r][c] = text[idx]
                    idx += 1
        return matrix

    # --------------------------------------------------
    # ENCRYPT
    # --------------------------------------------------

    def encrypt(self, data: bytes, key: str) -> bytes:
        rows, cols, route = self._parse_key(key)

        text = (
            data.decode("utf-8", errors="ignore")
            .upper()
            .replace(" ", "")
        )

        matrix = self._fill_rowwise(text, rows, cols)

        if route == "spiral":
            cipher = self._read_spiral(matrix, rows, cols)
        elif route == "column":
            cipher = self._read_column(matrix, rows, cols)
        else:
            cipher = self._read_diagonal(matrix, rows, cols)

        return cipher.encode("utf-8")

    # --------------------------------------------------
    # DECRYPT
    # --------------------------------------------------

    def decrypt(self, data: bytes, key: str) -> bytes:
        rows, cols, route = self._parse_key(key)

        text = data.decode("utf-8", errors="ignore").upper()

        if route == "spiral":
            matrix = self._write_spiral(text, rows, cols)
        elif route == "column":
            matrix = self._write_column(text, rows, cols)
        else:
            matrix = self._write_diagonal(text, rows, cols)

        plain = self._read_rowwise(matrix, rows, cols)
        return plain.encode("utf-8")
