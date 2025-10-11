"""
Kriptoloji algoritmaları modülü
Tüm şifreleme algoritmalarını içerir
"""

from .base import TextEncryptionAlgorithm
from .caesar import CaesarCipher
from .vigenere import VigenereCipher
from .affine import AffineCipher
from .substitution import SubstitutionCipher
from .rail_fence import RailFenceCipher

# Mevcut algoritmalar
AVAILABLE_ALGORITHMS = {
    'caesar': CaesarCipher,
    'vigenere': VigenereCipher,
    'affine': AffineCipher,
    'substitution': SubstitutionCipher,
    'rail_fence': RailFenceCipher
}

def get_algorithm(name: str) -> TextEncryptionAlgorithm:
    """
    Algoritma adına göre algoritma sınıfını döndürür
    
    Args:
        name: Algoritma adı
        
    Returns:
        Algoritma sınıfı
        
    Raises:
        ValueError: Algoritma bulunamazsa
    """
    if name not in AVAILABLE_ALGORITHMS:
        raise ValueError(f"Bilinmeyen algoritma: {name}")
    
    return AVAILABLE_ALGORITHMS[name]()

def get_available_algorithms() -> list:
    """
    Mevcut algoritmaların listesini döndürür
    
    Returns:
        Algoritma adları listesi
    """
    return list(AVAILABLE_ALGORITHMS.keys())

def get_algorithm_info(name: str) -> dict:
    """
    Algoritma hakkında bilgi döndürür
    
    Args:
        name: Algoritma adı
        
    Returns:
        Algoritma bilgileri
        
    Raises:
        ValueError: Algoritma bulunamazsa
    """
    algorithm = get_algorithm(name)
    return algorithm.get_info()

__all__ = [
    'TextEncryptionAlgorithm',
    'CaesarCipher',
    'VigenereCipher', 
    'AffineCipher',
    'SubstitutionCipher',
    'RailFenceCipher',
    'get_algorithm',
    'get_available_algorithms',
    'get_algorithm_info',
    'AVAILABLE_ALGORITHMS'
]