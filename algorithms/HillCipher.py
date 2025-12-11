from algorithms.BaseCipher import BaseCipher
from typing import Union

class HillCipher(BaseCipher):

    def __init__(self):
        super().__init__()
        self.name = "Hill Cipher"
        self.description = "Hill matris tabanlı şifreleme algoritması"
        self.key_type = "matrix"
        self.min_key_length = 4
        self.max_key_length = 16
        self.key_description = "2x2 veya 3x3 matris (ör: 1,2,3,4)"
        self.matrix_size = 2

    def encrypt(self, data: bytes, key: str) -> bytes:

        try:
            key_matrix = self._parse_key(key)

            data_str = data.decode('utf-8', errors='ignore')
            data_str = ''.join(c.upper() for c in data_str if c.isalpha())

            while len(data_str) % self.matrix_size != 0:
                data_str += 'X'

            result = ""

            for i in range(0, len(data_str), self.matrix_size):
                group = data_str[i:i + self.matrix_size]
                encrypted_group = self._encrypt_group(group, key_matrix)
                result += encrypted_group

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:

        try:
            key_matrix = self._parse_key(key)

            det = self._determinant(key_matrix)
            if det == 0:
                raise ValueError("Matris determinantı 0 olamaz")

            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                raise ValueError("Matris tersi hesaplanamıyor")

            adj_matrix = self._adjugate(key_matrix)
            inverse_matrix = self._matrix_multiply_scalar(adj_matrix, det_inv)
            inverse_matrix = self._matrix_mod(inverse_matrix, 26)

            data_str = data.decode('utf-8', errors='ignore')
            data_str = ''.join(c.upper() for c in data_str if c.isalpha())

            result = ""

            for i in range(0, len(data_str), self.matrix_size):
                group = data_str[i:i + self.matrix_size]
                decrypted_group = self._decrypt_group(group, inverse_matrix)
                result += decrypted_group

            return result.encode('utf-8')

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def _parse_key(self, key: str) -> list:
        try:
            key_values = [int(x.strip()) for x in key.split(',')]

            if len(key_values) == 4:
                self.matrix_size = 2
                matrix = [[key_values[0], key_values[1]],
                          [key_values[2], key_values[3]]]
            elif len(key_values) == 9:
                self.matrix_size = 3
                matrix = [[key_values[0], key_values[1], key_values[2]],
                          [key_values[3], key_values[4], key_values[5]],
                          [key_values[6], key_values[7], key_values[8]]]
            else:
                raise ValueError("Anahtar 4 (2x2) veya 9 (3x3) sayı içermeli")

            det = self._determinant(matrix)
            if det == 0:
                raise ValueError("Matris determinantı 0 olamaz")

            return matrix

        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar formatı: {str(e)}")

    def _encrypt_group(self, group: str, matrix: list) -> str:
        vector = [ord(c) - ord('A') for c in group]

        result_vector = self._matrix_vector_multiply(matrix, vector)
        result_vector = [x % 26 for x in result_vector]

        return ''.join(chr(int(x) + ord('A')) for x in result_vector)

    def _decrypt_group(self, group: str, inverse_matrix: list) -> str:
        vector = [ord(c) - ord('A') for c in group]

        result_vector = self._matrix_vector_multiply(inverse_matrix, vector)
        result_vector = [x % 26 for x in result_vector]

        result = ''.join(chr(int(x) + ord('A')) for x in result_vector)

        while result.endswith('X'):
            result = result[:-1]

        return result

    def _determinant(self, matrix: list) -> int:
        if len(matrix) == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        elif len(matrix) == 3:
            return (matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
                    matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
                    matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]))
        return 0

    def _adjugate(self, matrix: list) -> list:
        if len(matrix) == 2:
            return [[matrix[1][1], -matrix[0][1]],
                    [-matrix[1][0], matrix[0][0]]]
        elif len(matrix) == 3:
            return [[matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1],
                     -(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1]),
                     matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]],
                    [-(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]),
                     matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0],
                     -(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0])],
                    [matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0],
                     -(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0]),
                     matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]]]
        return matrix

    def _matrix_vector_multiply(self, matrix: list, vector: list) -> list:
        result = []
        for row in matrix:
            sum_val = 0
            for i, val in enumerate(row):
                if i < len(vector):
                    sum_val += val * vector[i]
            result.append(sum_val)
        return result

    def _matrix_multiply_scalar(self, matrix: list, scalar: int) -> list:
        return [[val * scalar for val in row] for row in matrix]

    def _matrix_mod(self, matrix: list, mod: int) -> list:
        return [[val % mod for val in row] for row in matrix]

    def _mod_inverse(self, a: int, m: int) -> int:
        a = a % m
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    def validate_key(self, key: str) -> bool:

        try:
            key_values = [int(x.strip()) for x in key.split(',')]

            if len(key_values) not in [4, 9]:
                return False

            if len(key_values) == 4:
                matrix = [[key_values[0], key_values[1]],
                          [key_values[2], key_values[3]]]
            else:
                matrix = [[key_values[0], key_values[1], key_values[2]],
                          [key_values[3], key_values[4], key_values[5]],
                          [key_values[6], key_values[7], key_values[8]]]

            det = self._determinant(matrix)
            if det == 0:
                return False

            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                return False

            return True

        except (ValueError, IndexError):
            return False
