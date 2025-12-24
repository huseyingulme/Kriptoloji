"""
Route Cipher - Rota Tabanlı Şifreleme
Metin bir matrise yerleştirilir ve belirli bir rota (spiral, row, column, diagonal)
izlenerek okunur.
"""

from algorithms.BaseCipher import BaseCipher


class RouteCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Route Cipher"
        self.supports_binary = False
        self.description = "Matris içinde seçilen rota ile okuma tabanlı şifreleme"
        self.key_type = "string"
        self.min_key_length = 3
        self.max_key_length = 20
        self.key_description = (
            "Format: rows:cols:type -> Örnek: 3:3:spiral, 4:4:row, 3:3:column"
        )
        self.supports_binary = False

    # --------------------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------------------

    def _parse_key(self, key: str) -> tuple:
        try:
            parts = key.split(":")
            if len(parts) != 3:
                raise ValueError("Anahtar formatı 'rows:cols:route_type' olmalıdır.")

            rows = int(parts[0])
            cols = int(parts[1])
            route_type = parts[2].lower()

            if rows < 2 or cols < 2:
                raise ValueError("Satır/sütun en az 2 olmalıdır.")

            if route_type not in ("spiral", "row", "column", "diagonal"):
                raise ValueError("Rota spiral, row, column veya diagonal olabilir.")

            return rows, cols, route_type

        except Exception as e:
            raise ValueError(f"Anahtar parse hatası: {str(e)}")

    # --------------------------------------------------------------
    # MATRIX OPERATIONS
    # --------------------------------------------------------------

    def _fill_matrix_rowwise(self, text, rows, cols):
        """Matris satır satır doldurulur."""
        matrix = [["" for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for r in range(rows):
            for c in range(cols):
                matrix[r][c] = text[idx] if idx < len(text) else ""
                idx += 1
        return matrix

    def _read_matrix_rowwise(self, matrix, rows, cols):
        """Matris satır satır okunur."""
        return "".join(matrix[r][c] for r in range(rows) for c in range(cols))

    # --------------------------------------------------------------
    # ROUTE READERS
    # --------------------------------------------------------------

    def _read_spiral(self, matrix, rows, cols):
        result = []
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1

        while top <= bottom and left <= right:

            for c in range(left, right + 1):
                result.append(matrix[top][c])
            top += 1

            for r in range(top, bottom + 1):
                result.append(matrix[r][right])
            right -= 1

            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(matrix[bottom][c])
                bottom -= 1

            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(matrix[r][left])
                left += 1

        return "".join(result)

    def _write_spiral(self, text, rows, cols):
        """Decrypt için spiral sıraya uygun şekilde matris doldurma."""
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

    # --------------------------------------------------------------
    # ENCRYPT
    # --------------------------------------------------------------

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            rows, cols, route_type = self._parse_key(key)

            text = (
                data.decode("utf-8", errors="ignore")
                .upper()
                .replace(" ", "")
            )

            matrix = self._fill_matrix_rowwise(text, rows, cols)

            if route_type == "spiral":
                encrypted = self._read_spiral(matrix, rows, cols)
            elif route_type == "row":
                encrypted = self._read_row(matrix, rows, cols)
            elif route_type == "column":
                encrypted = self._read_column(matrix, rows, cols)
            else:
                encrypted = self._read_diagonal(matrix, rows, cols)

            return encrypted.encode("utf-8")

        except Exception as e:
            raise Exception(f"Route şifreleme hatası: {str(e)}")

    # --------------------------------------------------------------
    # DECRYPT
    # --------------------------------------------------------------

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            rows, cols, route_type = self._parse_key(key)

            text = data.decode("utf-8", errors="ignore").upper()

            if route_type == "spiral":
                matrix = self._write_spiral(text, rows, cols)
            elif route_type == "row":
                matrix = self._fill_matrix_rowwise(text, rows, cols)
            elif route_type == "column":
                matrix = self._write_column(text, rows, cols)
            else:
                matrix = self._write_diagonal(text, rows, cols)

            decrypted = self._read_matrix_rowwise(matrix, rows, cols)
            return decrypted.encode("utf-8")

        except Exception as e:
            raise Exception(f"Route çözme hatası: {str(e)}")
