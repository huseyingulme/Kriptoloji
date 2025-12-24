from algorithms.BaseCipher import BaseCipher


class ColumnarTranspositionCipher(BaseCipher):
    """
    Columnar Transposition (Sütunlu Yer Değiştirme) Şifreleme Algoritması.

    Mantık:
        - Anahtar kelimedeki harflerin alfabetik sırası belirlenir.
        - Metin satırlara ayrılır, sütunlar anahtar sırasına göre okunur.
    """

    def __init__(self):
        super().__init__()
        self.name = "Columnar Transposition Cipher"
        self.supports_binary = False
        self.description = "Sütunlu yer değiştirme tabanlı klasik şifreleme"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 20
        self.key_description = "Anahtar kelime (sütun sırasını belirler)"

    # ----------------------------------------------------------------------

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Columnar transposition ile şifreleme.
        """
        try:
            key = key.strip().upper()
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar.")

            text = data.decode("utf-8", errors="ignore").replace(" ", "").upper()

            if len(text) == 0:
                return b""

            key_order = self._get_key_order(key)
            num_cols = len(key_order)

            # Metni sütun sayısına tamamla
            padding = (num_cols - (len(text) % num_cols)) % num_cols
            text += "X" * padding

            # Matris oluştur
            matrix = [
                list(text[i:i + num_cols])
                for i in range(0, len(text), num_cols)
            ]

            # Sütunları anahtar sırasına göre oku
            encrypted = ""
            for col in key_order:
                for row in matrix:
                    encrypted += row[col]

            return encrypted.encode("utf-8")

        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    # ----------------------------------------------------------------------

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Columnar transposition çözme işlemi.
        """
        try:
            key = key.strip().upper()
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar.")

            text = data.decode("utf-8", errors="ignore").upper()
            if len(text) == 0:
                return b""

            key_order = self._get_key_order(key)
            num_cols = len(key_order)
            num_rows = len(text) // num_cols

            # Boş matris oluştur
            matrix = [[''] * num_cols for _ in range(num_rows)]

            # Sütunları sırayla doldur
            index = 0
            for col in key_order:
                for row in range(num_rows):
                    matrix[row][col] = text[index]
                    index += 1

            # Satır satır oku
            decrypted = "".join("".join(row) for row in matrix)

            # X padlerini temizle (sadece sondakileri)
            decrypted = decrypted.rstrip("X")

            return decrypted.encode("utf-8")

        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    # ----------------------------------------------------------------------

    def _get_key_order(self, key: str) -> list:
        """
        Anahtar kelimeyi alfabetik olarak sıralayıp,
        harflerin gerçek pozisyonlarını döndürür.
        """
        indexed_chars = list(enumerate(key))
        # Örn: "ZEBRA" → [(0,'Z'), (1,'E'), (2,'B'), ...]

        # Harfleri alfabetik sıraya göre, index eşitliklerinde index sırasına göre sırala
        sorted_chars = sorted(indexed_chars, key=lambda x: (x[1], x[0]))

        # Yeni sıralamadaki sütun indexleri
        return [pair[0] for pair in sorted_chars]

    # ----------------------------------------------------------------------

    def validate_key(self, key: str) -> bool:
        """
        Key doğrulama:
        - boş olamaz
        - sadece harflerden oluşabilir
        - uzunluk sınırına uymalı
        """
        if not key:
            return False

        if not key.isalpha():
            return False

        if not (self.min_key_length <= len(key) <= self.max_key_length):
            return False

        return True
