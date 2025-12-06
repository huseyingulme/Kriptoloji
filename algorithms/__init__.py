from .base import TextEncryptionAlgorithm
from .caesar import CaesarCipher
from .vigenere import VigenereCipher
from .affine import AffineCipher
from .substitution import SubstitutionCipher
from .rail_fence import RailFenceCipher
from .des import DESCipher

AVAILABLE_ALGORITHMS = {
    'caesar': CaesarCipher,
    'vigenere': VigenereCipher,
    'affine': AffineCipher,
    'substitution': SubstitutionCipher,
    'rail_fence': RailFenceCipher,
    'des': DESCipher
}

def get_algorithm(name: str) -> TextEncryptionAlgorithm:
    if name not in AVAILABLE_ALGORITHMS:
        raise ValueError(f"Bilinmeyen algoritma: {name}")

    return AVAILABLE_ALGORITHMS[name]()

def get_available_algorithms() -> list:
    return list(AVAILABLE_ALGORITHMS.keys())

def get_algorithm_info(name: str) -> dict:
    algorithm = get_algorithm(name)
    return algorithm.get_info()

__all__ = [
    'TextEncryptionAlgorithm',
    'CaesarCipher',
    'VigenereCipher',
    'AffineCipher',
    'SubstitutionCipher',
    'RailFenceCipher',
    'DESCipher',
    'get_algorithm',
    'get_available_algorithms',
    'get_algorithm_info',
    'AVAILABLE_ALGORITHMS'
]
