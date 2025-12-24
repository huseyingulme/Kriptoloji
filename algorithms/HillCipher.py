from algorithms.BaseCipher import BaseCipher


class HillCipher(BaseCipher):
    """
    Hill Cipher (2x2 veya 3x3 matris) şifreleme algoritması.

    Alfabe: A-Z → 0-25
    Formül:
        C = (K * P) mod 26
        P = (K^-1 * C) mod 26
    """

    def __init__(self):
        super().__init__()
        self.name = "Hill Cipher"
        self.supports_binary = False
        self.description = "Matris tabanlı klasik şifreleme algoritması"
        self.key_type = "matrix"
        self.key_description = "2x2 veya 3x3 matris — örnek: 1,2,3,4"
        self.min_key_length = 4
        self.max_key_length = 9
        self.matrix_size = 2

    # =======================================================================
    # ENCRYPT
    # =======================================================================

    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            key_matrix = self._parse_key(key)

            text = data.decode("utf-8", errors="ignore")
            text = "".join(c.upper() for c in text if c.isalpha())
            if not text:
                return data

            # Blok uzunluğunu matrise göre tamamla
            while len(text) % self.matrix_size != 0:
                text += "X"

            result = ""

            for i in range(0, len(text), self.matrix_size):
                block = text[i:i + self.matrix_size]
                encrypted = self._encrypt_block(block, key_matrix)
                result += encrypted

            return result.encode("utf-8")

        except Exception as e:
            from shared.utils import Logger
            Logger.error(f"Hill Cipher hatası: {str(e)}", "HillCipher")
            raise e

    # =======================================================================
    # DECRYPT
    # =======================================================================

    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            key_matrix = self._parse_key(key)

            det = self._determinant(key_matrix) % 26
            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                raise ValueError("Anahtar matrisinin tersi yoktur (mod 26).")

            adj = self._adjugate(key_matrix)
            inv_matrix = self._matrix_mod(
                self._matrix_multiply_scalar(adj, det_inv),
                26
            )

            text = data.decode("utf-8", errors="ignore")
            text = "".join(c.upper() for c in text if c.isalpha())

            result = ""

            for i in range(0, len(text), self.matrix_size):
                block = text[i:i + self.matrix_size]
                decrypted = self._decrypt_block(block, inv_matrix)
                result += decrypted

            return result.rstrip("X").encode("utf-8")

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    # =======================================================================
    # KEY PARSE
    # =======================================================================

    def _parse_key(self, key: str) -> list:
        """
        Anahtarı string'den matrise dönüştürür.
        4 eleman → 2x2
        9 eleman → 3x3
        """
        nums = [int(x.strip()) for x in key.split(",")]

        if len(nums) == 4:
            self.matrix_size = 2
            matrix = [
                [nums[0], nums[1]],
                [nums[2], nums[3]]
            ]
        elif len(nums) == 9:
            self.matrix_size = 3
            matrix = [
                [nums[0], nums[1], nums[2]],
                [nums[3], nums[4], nums[5]],
                [nums[6], nums[7], nums[8]]
            ]
        else:
            raise ValueError("Anahtar 2x2 (4 sayı) veya 3x3 (9 sayı) olmalıdır.")

        det = self._determinant(matrix) % 26
        if self._mod_inverse(det, 26) is None:
            raise ValueError("Matris terslenemez, determinant mod 26 için invers yok.")

        return matrix

    # =======================================================================
    # BLOCK OPERATIONS
    # =======================================================================

    def _encrypt_block(self, block: str, matrix: list) -> str:
        vector = [ord(c) - 65 for c in block]
        result = self._matrix_vector_multiply(matrix, vector)
        return "".join(chr((x % 26) + 65) for x in result)

    def _decrypt_block(self, block: str, inverse_matrix: list) -> str:
        vector = [ord(c) - 65 for c in block]
        result = self._matrix_vector_multiply(inverse_matrix, vector)
        return "".join(chr((x % 26) + 65) for x in result)

    # =======================================================================
    # MATRIX UTILITIES
    # =======================================================================

    def _determinant(self, m: list) -> int:
        """2x2 veya 3x3 determinant"""
        if len(m) == 2:
            return m[0][0] * m[1][1] - m[0][1] * m[1][0]

        if len(m) == 3:
            return (
                m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) -
                m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
                m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
            )
        raise ValueError("Matris boyutu geçersiz.")

    def _adjugate(self, m: list) -> list:
        """Ters hesaplamak için adjoint (adjugate) matrisi döndürür."""
        if len(m) == 2:
            return [
                [m[1][1], -m[0][1]],
                [-m[1][0], m[0][0]]
            ]

        if len(m) == 3:
            return [
                [
                    m[1][1] * m[2][2] - m[1][2] * m[2][1],
                    -(m[0][1] * m[2][2] - m[0][2] * m[2][1]),
                    m[0][1] * m[1][2] - m[0][2] * m[1][1]
                ],
                [
                    -(m[1][0] * m[2][2] - m[1][2] * m[2][0]),
                    m[0][0] * m[2][2] - m[0][2] * m[2][0],
                    -(m[0][0] * m[1][2] - m[0][2] * m[1][0])
                ],
                [
                    m[1][0] * m[2][1] - m[1][1] * m[2][0],
                    -(m[0][0] * m[2][1] - m[0][1] * m[2][0]),
                    m[0][0] * m[1][1] - m[0][1] * m[1][0]
                ]
            ]

        raise ValueError("Matris boyutu desteklenmiyor.")

    # ----------------------------------------------------------------------

    def _matrix_vector_multiply(self, m: list, v: list) -> list:
        return [sum(m[i][j] * v[j] for j in range(len(v))) for i in range(len(m))]

    def _matrix_multiply_scalar(self, m: list, k: int) -> list:
        return [[val * k for val in row] for row in m]

    def _matrix_mod(self, m: list, mod: int) -> list:
        return [[val % mod for val in row] for row in m]

    # =======================================================================
    # MODULAR INVERSE
    # =======================================================================

    def _mod_inverse(self, a: int, m: int) -> int:
        """a*x ≡ 1 (mod m) denklemini çözer."""
        a %= m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    # =======================================================================
    # KEY VALIDATION
    # =======================================================================

    def validate_key(self, key: str) -> bool:
        try:
            nums = [int(x.strip()) for x in key.split(",")]
            if len(nums) not in (4, 9):
                return False

            # Matrise çevir
            if len(nums) == 4:
                matrix = [[nums[0], nums[1]], [nums[2], nums[3]]]
            else:
                matrix = [
                    [nums[0], nums[1], nums[2]],
                    [nums[3], nums[4], nums[5]],
                    [nums[6], nums[7], nums[8]]
                ]

            det = self._determinant(matrix) % 26
            return self._mod_inverse(det, 26) is not None

        except Exception:
            return False
