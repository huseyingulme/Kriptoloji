"""
Pigpen Cipher (Mason Şifresi) - Sembol Tabanlı Şifreleme
Her harf özel bir sembol ile temsil edilir.
"""

from algorithms.BaseCipher import BaseCipher


class PigpenCipher(BaseCipher):
    """Pigpen Cipher - Mason Sembol Şifreleme"""

    def __init__(self):
        super().__init__()
        self.name = "Pigpen Cipher"
        self.description = "Harflere özel semboller atayan sembol tabanlı klasik şifreleme tekniği"
        self.key_type = "none"
        self.min_key_length = 0
        self.max_key_length = 0
        self.key_description = "Bu şifreleme tekniği anahtar gerektirmez."
        self.supports_binary = False

        # Pigpen sembol tablosu (Standart Mason sembolleri)
        self.symbol_map = {
            # Kare seti
            'A': '┌', 'B': '┐', 'C': '└', 'D': '┘',
            'E': '├', 'F': '┤', 'G': '┬', 'H': '┴',
            'I': '┼', 'J': '┼',     # I ve J aynı sembol

            # Kare + nokta seti
            'K': '┌•', 'L': '┐•', 'M': '└•', 'N': '┘•',
            'O': '├•', 'P': '┤•', 'Q': '┬•', 'R': '┴•',
            'S': '┼•',

            # X seti
            'T': '╳', 'U': '╱', 'V': '╲',
            'W': '╳•', 'X': '╱•', 'Y': '╲•',

            # Z son sembol
            'Z': '◎'
        }

        # Sembolden harfe dönüşüm
        self.reverse_map = {}
        for letter, symbol in self.symbol_map.items():
            # Aynı sembol varsa (örn: I ve J) ilk harfi seç
            if symbol not in self.reverse_map:
                self.reverse_map[symbol] = letter
            # J için I sembolü kullanılır
            if letter == "J":
                self.reverse_map[symbol] = "I"

    # ------------------------------------------------
    # Anahtar doğrulama (Pigpen anahtar istemez)
    # ------------------------------------------------
    def validate_key(self, key: str) -> bool:
        return True

    # ------------------------------------------------
    # Şifreleme
    # ------------------------------------------------
    def encrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode("utf-8", errors="ignore").upper()
            encrypted = []

            for ch in text:
                if ch.isalpha():
                    encrypted.append(self.symbol_map.get(ch, ch))
                elif ch == " ":
                    encrypted.append(" ")
                else:
                    encrypted.append(ch)

            return "".join(encrypted).encode("utf-8")

        except Exception as exc:
            raise Exception(f"Pigpen şifreleme hatası: {str(exc)}")

    # ------------------------------------------------
    # Çözme
    # ------------------------------------------------
    def decrypt(self, data: bytes, key: str) -> bytes:
        try:
            text = data.decode("utf-8", errors="ignore")
            decrypted = []

            i = 0
            while i < len(text):

                # Boşluk
                if text[i] == " ":
                    decrypted.append(" ")
                    i += 1
                    continue

                match = None

                # 2 karakterlik semboller (örn: ┌•)
                if i + 2 <= len(text):
                    two = text[i:i+2]
                    if two in self.reverse_map:
                        match = self.reverse_map[two]
                        i += 2

                # 1 karakterlik semboller (örn: ┌)
                if match is None:
                    one = text[i]
                    if one in self.reverse_map:
                        match = self.reverse_map[one]
                        i += 1

                # Sembol değilse direkt ekle
                if match is None:
                    decrypted.append(text[i])
                    i += 1
                else:
                    decrypted.append(match)

            return "".join(decrypted).encode("utf-8")

        except Exception as exc:
            raise Exception(f"Pigpen çözme hatası: {str(exc)}")
