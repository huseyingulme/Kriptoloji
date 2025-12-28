"""
AES Dynamic S-Box Generation

Bu modül, statik bir tablo yerine anahtara bağlı veya standart AES 
S-Box'ını matematiksel olarak üreten mantığı içerir.
"""

from algorithms.aes_manual import gf

def generate_sbox() -> list:
    """
    Standart AES S-Box'ını matematiksel olarak üretir.
    Adımlar:
    1. 0'dan 255'e kadar her sayı için GF(2^8) tersini bul.
    2. Affine dönüşümü uygula.
    """
    sbox = [0] * 256
    for i in range(256):
        # 1. Çarpımsal ters
        inv = gf.inverse(i)
        
        # 2. Affine Dönüşümü: s = b + (b << 1) + (b << 2) + (b << 3) + (b << 4) + 0x63
        # Bu işlem bit bazlı bir matris çarpımı + sabit XOR'dur.
        s = inv
        x = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[i] = s ^ 0x63
        
    return sbox

def generate_inverse_sbox(sbox: list) -> list:
    """Verilen bir S-Box'ın tersini üretir."""
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox

def generate_dynamic_sbox(seed_key: bytes) -> list:
    """
    Anahtara bağlı dinamik S-Box üretir.
    NOT: Akademik olarak "Dinamik S-Box" kullanımı, şifreleme gücünü 
    lineer kriptanalize karşı değiştirebilir.
    """
    # Basit bir örnek: Standart S-Box'ı anahtarın XOR toplamı kadar döndür
    base_sbox = generate_sbox()
    shift = sum(seed_key) % 256
    dynamic_sbox = base_sbox[shift:] + base_sbox[:shift]
    return dynamic_sbox
