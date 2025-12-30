"""
AES S-Box Mathematical Generation (Galois Field Foundations)

Bu modül, S-Box değerlerini statik bir tablo yerine matematiksel 
temellerle (GF(2^8)) üretir.

KRİPTO FELSEFESİ:
"AES bir ezber tablo değil, bir matematiksel dönüşümdür."
"""

from algorithms.aes_manual import gf

def generate_sbox() -> list:
    """
    Standart AES S-Box'ını matematiksel olarak üretir.
    Adımlar:
    1. GF(2^8) üzerinde çarpımsal tersini bul (Multiplicative Inverse).
    2. Afin Dönüşümü uygula (Affine Transformation).
    """
    sbox = [0] * 256
    for i in range(256):
        # 1. Adım: GF(2^8) tersini bul
        inv = gf.inverse(i)
        
        # 2. Adım: Affine Dönüşümü (Bit bazlı matris çarpımı + 0x63 Sabiti)
        s = inv
        x = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[i] = s ^ 0x63
        
    return sbox

def generate_inverse_sbox(sbox: list = None) -> list:
    """S-Box'ın tersini (Decryption için) üretir."""
    if sbox is None:
        sbox = generate_sbox()
        
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox

def generate_dynamic_sbox(seed_key: bytes) -> list:
    """
    Anahtara bağlı dinamik S-Box üretir.
    Akademik Amaç: Standart S-Box'ın anahtar bağımlı permutasyonu.
    """
    base_sbox = generate_sbox()
    shift = sum(seed_key) % 256
    return base_sbox[shift:] + base_sbox[:shift]
