from algorithms.BaseCipher import BaseCipher


class HillCipher(BaseCipher):
    """
    Hill Cipher – Matris tabanlı klasik şifreleme algoritması

    Alfabe: A-Z → 0-25
    Şifreleme : C = (K * P) mod 26
    Çözme     : P = (K⁻¹ * C) mod 26
    """

    def __init__(self):
        super().__init__()
        self.name = "Hill Cipher"
        self.description = "Matris tabanlı klasik şifreleme algoritması"
        self.key_type = "matrix"
        self.key_description = "2x2 veya 3x3 matris (örn: 3,3,2,5)"
        self.supports_binary = False

    # ==================================================
    # KEY
    # ==================================================

    def validate_key(self, key: str) -> bool:
        try:
            matrix = self._parse_key(key)
            det = self._determinant(matrix) % 26
            return self._mod_inverse(det, 26) is not None
        except Exception:
            return False

    def _parse_key(self, key: str) -> list:
        nums = [int(x.strip()) for x in key.split(",")]

        if len(nums) == 4:
            return [[nums[0], nums[1]],
                    [nums[2], nums[3]]]

        if len(nums) == 9:
            return [[nums[0], nums[1], nums[2]],
                    [nums[3], nums[4], nums[5]],
                    [nums[6], nums[7], nums[8]]]

        raise ValueError("Anahtar 2x2 (4 sayı) veya 3x3 (9 sayı) olmalıdır.")

    # ==================================================
    # ENCRYPT
    # ==================================================

    def encrypt(self, data: bytes, key: str) -> bytes:
        matrix = self._parse_key(key)
        size = len(matrix)

        text = "".join(chr(b) for b in data).upper()
        text = "".join(c for c in text if c.isalpha())

        while len(text) % size != 0:
            text += "X"

        result = ""

        for i in range(0, len(text), size):
            block = text[i:i + size]
            result += self._process_block(block, matrix)

        return result.encode("utf-8")

    # ==================================================
    # DECRYPT
    # ==================================================

    def decrypt(self, data: bytes, key: str) -> bytes:
        matrix = self._parse_key(key)
        size = len(matrix)

        det = self._determinant(matrix) % 26
        det_inv = self._mod_inverse(det, 26)
        if det_inv is None:
            raise ValueError("Anahtar matrisinin mod 26 tersi yoktur.")

        adj = self._adjugate(matrix)
        inv_matrix = self._matrix_mod(
            self._matrix_scalar(adj, det_inv), 26
        )

        text = "".join(chr(b) for b in data).upper()
        text = "".join(c for c in text if c.isalpha())

        result = ""

        for i in range(0, len(text), size):
            block = text[i:i + size]
            result += self._process_block(block, inv_matrix)

        return result.rstrip("X").encode("utf-8")

    # ==================================================
    # BLOCK
    # ==================================================

    def _process_block(self, block: str, matrix: list) -> str:
        vector = [ord(c) - 65 for c in block]
        multiplied = self._matrix_vector(matrix, vector)
        return "".join(chr((x % 26) + 65) for x in multiplied)

    # ==================================================
    # MATRIX MATH
    # ==================================================

    def _matrix_vector(self, m: list, v: list) -> list:
        return [sum(m[i][j] * v[j] for j in range(len(v)))
                for i in range(len(m))]

    def _matrix_scalar(self, m: list, k: int) -> list:
        return [[val * k for val in row] for row in m]

    def _matrix_mod(self, m: list, mod: int) -> list:
        return [[val % mod for val in row] for row in m]

    # ==================================================
    # DETERMINANT & ADJUGATE
    # ==================================================

    def _determinant(self, m: list) -> int:
        if len(m) == 2:
            return m[0][0]*m[1][1] - m[0][1]*m[1][0]

        if len(m) == 3:
            return (
                m[0][0]*(m[1][1]*m[2][2] - m[1][2]*m[2][1]) -
                m[0][1]*(m[1][0]*m[2][2] - m[1][2]*m[2][0]) +
                m[0][2]*(m[1][0]*m[2][1] - m[1][1]*m[2][0])
            )

        raise ValueError("Geçersiz matris boyutu.")

    def _adjugate(self, m: list) -> list:
        if len(m) == 2:
            return [
                [m[1][1], -m[0][1]],
                [-m[1][0], m[0][0]]
            ]

        if len(m) == 3:
            return [
                [
                    m[1][1]*m[2][2] - m[1][2]*m[2][1],
                    -(m[0][1]*m[2][2] - m[0][2]*m[2][1]),
                    m[0][1]*m[1][2] - m[0][2]*m[1][1]
                ],
                [
                    -(m[1][0]*m[2][2] - m[1][2]*m[2][0]),
                    m[0][0]*m[2][2] - m[0][2]*m[2][0],
                    -(m[0][0]*m[1][2] - m[0][2]*m[1][0])
                ],
                [
                    m[1][0]*m[2][1] - m[1][1]*m[2][0],
                    -(m[0][0]*m[2][1] - m[0][1]*m[2][0]),
                    m[0][0]*m[1][1] - m[0][1]*m[1][0]
                ]
            ]

        raise ValueError("Adjugate desteklenmiyor.")

    # ==================================================
    # MODULAR INVERSE
    # ==================================================

    def _mod_inverse(self, a: int, mod: int) -> int | None:
        a %= mod
        for x in range(1, mod):
            if (a * x) % mod == 1:
                return x
        return None
