import sys
import os
from typing import Dict, Any, List
import base64
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algorithms import get_algorithm, get_available_algorithms, get_algorithm_info


class EncryptionService:
    def __init__(self):
        self.available_algorithms = get_available_algorithms()

    # ----------------------- Text Encryption / Decryption -----------------------
    def encrypt_text(self, text: str, algorithm: str, **params) -> Dict[str, Any]:
        return self._execute_cipher("encrypt", text, algorithm, params)

    def decrypt_text(
        self, encrypted_text: str, algorithm: str, **params
    ) -> Dict[str, Any]:
        return self._execute_cipher("decrypt", encrypted_text, algorithm, params)

    # ----------------------- File Encryption / Decryption -----------------------
    def encrypt_file(
        self, file_data: bytes, algorithm: str, **params
    ) -> Dict[str, Any]:
        try:
            cipher = get_algorithm(algorithm)
            file_str = base64.b64encode(file_data).decode("utf-8")
            encrypted_str = cipher.encrypt(file_str, **params)
            encrypted_bytes = base64.b64encode(encrypted_str.encode("utf-8"))

            return {
                "success": True,
                "encrypted_data": encrypted_bytes.decode("utf-8"),
                "algorithm": algorithm,
                "params": params,
                "original_size": len(file_data),
                "encrypted_size": len(encrypted_bytes),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return self._error_result(e, algorithm, params)

    def decrypt_file(
        self, encrypted_data: str, algorithm: str, **params
    ) -> Dict[str, Any]:
        try:
            cipher = get_algorithm(algorithm)
            encrypted_bytes = base64.b64decode(encrypted_data)
            encrypted_str = encrypted_bytes.decode("utf-8")
            decrypted_str = cipher.decrypt(encrypted_str, **params)
            decrypted_bytes = base64.b64decode(decrypted_str)

            return {
                "success": True,
                "file_data": base64.b64encode(decrypted_bytes).decode("utf-8"),
                "algorithm": algorithm,
                "params": params,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return self._error_result(e, algorithm, params)

    # ----------------------- Algorithm Info / Validation -----------------------
    def get_available_algorithms(self) -> List[str]:
        return self.available_algorithms.copy()

    def get_algorithm_info(self, algorithm: str) -> Dict[str, Any]:
        try:
            return get_algorithm_info(algorithm)
        except ValueError as e:
            return {"success": False, "error": str(e)}

    def validate_algorithm_params(
        self, algorithm: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            cipher = get_algorithm(algorithm)
            is_valid = cipher.validate_params(params)
            missing = [p for p in cipher.required_params if p not in params]

            return {
                "success": True,
                "valid": is_valid,
                "required_params": cipher.required_params,
                "missing_params": missing,
            }
        except Exception as e:
            return self._error_result(e, algorithm, params)

    # ----------------------- Private Helpers -----------------------
    def _execute_cipher(
        self, operation: str, data: str, algorithm: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            cipher = get_algorithm(algorithm)
            result_data = getattr(cipher, operation)(data, **params)
            key = "encrypted_data" if operation == "encrypt" else "decrypted_data"

            return {
                "success": True,
                key: result_data,
                "algorithm": algorithm,
                "params": params,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return self._error_result(e, algorithm, params)

    def _error_result(
        self, exception: Exception, algorithm: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "error": str(exception),
            "algorithm": algorithm,
            "params": params,
        }


encryption_service = EncryptionService()
