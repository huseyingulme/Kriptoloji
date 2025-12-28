"""
Galois Field GF(2^8) Operations

Bu modül, AES algoritmasında kullanılan sonlu alan aritmetiğini sağlar.
İrreducible polinom (indirgenemez polinom): P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
"""

def multiply(a: int, b: int) -> int:
    """
    GF(2^8) üzerinde iki sayıyı çarpar.
    Rus Köylü Çarpma (Russian Peasant Multiplication) algoritması kullanılır.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi_bit:
            a ^= 0x1B  # x^8 mod x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

def inverse(n: int) -> int:
    """
    GF(2^8) üzerinde bir sayının çarpımsal tersini bulur.
    Genişletilmiş Öklid Algoritması veya Brute-force kullanılabilir.
    255 eleman olduğu için brute-force pratiktir.
    """
    if n == 0:
        return 0
    for i in range(1, 256):
        if multiply(n, i) == 1:
            return i
    return 0
