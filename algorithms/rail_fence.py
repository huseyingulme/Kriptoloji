from .base import TextEncryptionAlgorithm
from typing import Union, List

class RailFenceCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Rail Fence")
        self.required_params = ['rails']

    def _create_rails(self, text: str, num_rails: int) -> List[List[str]]:
        rails = [[] for _ in range(num_rails)]
        rail_index = 0
        direction = 1

        for char in text:
            rails[rail_index].append(char)

            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1

            rail_index += direction

        return rails

    def _get_rail_positions(self, length: int, num_rails: int) -> List[int]:
        positions = []
        rail_index = 0
        direction = 1

        for i in range(length):
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

        num_rails = int(kwargs['rails'])

        if num_rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")

        text = data if isinstance(data, str) else data.decode('utf-8')
        processed_text = self._prepare_text(text)

        if len(processed_text) == 0:
            return processed_text

        rails = self._create_rails(processed_text, num_rails)

        result = []
        for rail in rails:
            result.extend(rail)

        return ''.join(result)

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: rails")

        num_rails = int(kwargs['rails'])

        if num_rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")

        text = data if isinstance(data, str) else data.decode('utf-8')
        processed_text = self._prepare_text(text)

        if len(processed_text) == 0:
            return processed_text

        positions = self._get_rail_positions(len(processed_text), num_rails)
        rail_lengths = [positions.count(i) for i in range(num_rails)]

        rails = []
        start = 0
        for length in rail_lengths:
            rails.append(list(processed_text[start:start + length]))
            start += length

        result = []
        rail_index = 0
        direction = 1
        rail_positions = [0] * num_rails

        for _ in range(len(processed_text)):
            result.append(rails[rail_index][rail_positions[rail_index]])
            rail_positions[rail_index] += 1

            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1

            rail_index += direction

        return ''.join(result)

    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'Zikzak desen tabanlı şifreleme. Metin ray sayısı kadar satırda zikzak şeklinde yazılır.',
            'required_params': ['rails'],
            'param_descriptions': {
                'rails': 'Ray sayısı (en az 2, genelde 3-5 arası kullanılır)'
            }
        })
        return info
