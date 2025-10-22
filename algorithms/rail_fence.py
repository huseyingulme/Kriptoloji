from .base import TextEncryptionAlgorithm
from typing import Union, List


class RailFenceCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Rail Fence")
        self.required_params = ["rails"]

    def _get_rail_positions(self, length: int, num_rails: int) -> List[int]:
        positions = []
        rail_index = 0
        direction = 1
        for _ in range(length):
            positions.append(rail_index)
            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1
            rail_index += direction
        return positions

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: rails")
        num_rails = int(kwargs["rails"])
        if num_rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        if len(text) == 0:
            return text
        rails = ["" for _ in range(num_rails)]
        rail_index = 0
        direction = 1
        for ch in text:
            rails[rail_index] += ch
            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1
            rail_index += direction
        return "".join(rails)

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: rails")
        num_rails = int(kwargs["rails"])
        if num_rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        if len(text) == 0:
            return text
        positions = self._get_rail_positions(len(text), num_rails)
        rail_lengths = [positions.count(i) for i in range(num_rails)]
        rails = []
        start = 0
        for length in rail_lengths:
            rails.append(list(text[start : start + length]))
            start += length
        result_chars = []
        rail_index = 0
        direction = 1
        rail_ptrs = [0] * num_rails
        for _ in range(len(text)):
            result_chars.append(rails[rail_index][rail_ptrs[rail_index]])
            rail_ptrs[rail_index] += 1
            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1
            rail_index += direction
        return "".join(result_chars)

    def get_info(self):
        info = super().get_info()
        info.update(
            {
                "description": "Zikzak deseniyle metni raylara yerleştirip okuyan klasik şifreleme.",
                "required_params": ["rails"],
                "param_descriptions": {"rails": "Ray sayısı (en az 2)"},
            }
        )
        return info
