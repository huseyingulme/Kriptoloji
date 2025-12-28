from algorithms.BaseCipher import BaseCipher

class VigenereCipher(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Polyalphabetic Substitution Cipher
    A method of encrypting alphabetic text by using a series of interwoven Caesar ciphers.

    🔑 [Key Management]
    - Uses a keyword that is repeated to match the plaintext length.
    - Standard keys are managed through the system's Key Management module.

    🧮 [Mathematical Foundation]
    - Operates over the Finite Field GF(26).
    - Encryption: Ci = (Pi + Ki) mod 26
    - Decryption: Pi = (Ci - Ki) mod 26
    - Each character represents an element in GF(26).
    """

    def __init__(self):
        super().__init__()
        self.name = "Vigenère Cipher"
        self.description = "Çok alfabeli kaydırma tabanlı klasik şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 50
        self.key_description = "Sadece harflerden oluşan anahtar (A-Z, a-z)"
        self.supports_binary = False

    # --------------------------------------------------
    # Key doğrulama
    # --------------------------------------------------
    def validate_key(self, key: str) -> bool:
        if not key:
            return False
        if not key.isalpha():
            return False
        return self.min_key_length <= len(key) <= self.max_key_length

    # --------------------------------------------------
    # Key hazırlama (A-Z → 0-25)
    # --------------------------------------------------
    def _prepare_key(self, key: str) -> list[int]:
        """
        Anahtarı 0–25 arası sayılara çevirir.
        Örn: 'KEY' → [10, 4, 24]
        """
        if not key.isalpha():
            raise ValueError("Anahtar yalnızca harflerden oluşmalıdır.")

        return [ord(c.upper()) - ord('A') for c in key]

    # --------------------------------------------------
    # ŞİFRELEME
    # Ci = (Pi + Ki) mod 26
    # --------------------------------------------------
    def encrypt(self, data: bytes, key: str) -> bytes:
        key_nums = self._prepare_key(key)
        result = []
        key_index = 0

        for byte in data:
            char = chr(byte)

            if char.isupper():
                p = ord(char) - ord('A')
                k = key_nums[key_index % len(key_nums)]
                c = (p + k) % 26
                result.append(chr(c + ord('A')))
                key_index += 1

            elif char.islower():
                p = ord(char) - ord('a')
                k = key_nums[key_index % len(key_nums)]
                c = (p + k) % 26
                result.append(chr(c + ord('a')))
                key_index += 1

            else:
                result.append(char)

        return ''.join(result).encode("utf-8")

    # --------------------------------------------------
    # ÇÖZME
    # Pi = (Ci - Ki + 26) mod 26
    # --------------------------------------------------
    def decrypt(self, data: bytes, key: str) -> bytes:
        key_nums = self._prepare_key(key)
        result = []
        key_index = 0

        for byte in data:
            char = chr(byte)

            if char.isupper():
                c = ord(char) - ord('A')
                k = key_nums[key_index % len(key_nums)]
                p = (c - k + 26) % 26
                result.append(chr(p + ord('A')))
                key_index += 1

            elif char.islower():
                c = ord(char) - ord('a')
                k = key_nums[key_index % len(key_nums)]
                p = (c - k + 26) % 26
                result.append(chr(p + ord('a')))
                key_index += 1

            else:
                result.append(char)

        return ''.join(result).encode("utf-8")
