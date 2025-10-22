import os
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime


class FileManager:
    def __init__(self, base_dir: str = "EncryptedFiles"):
        self.base_dir = base_dir
        self.encrypted_dir = os.path.join(base_dir, "encrypted")
        self.metadata_dir = os.path.join(base_dir, "metadata")
        for directory in [self.base_dir, self.encrypted_dir, self.metadata_dir]:
            os.makedirs(directory, exist_ok=True)

    def save_encrypted_file(
        self,
        file_data: bytes,
        algorithm: str,
        params: Dict[str, Any],
        original_filename: Optional[str] = None,
    ) -> str:
        file_id = str(uuid.uuid4())
        if original_filename:
            name, ext = os.path.splitext(original_filename)
            filename = f"{name}_{algorithm}_{datetime.now():%Y%m%d_%H%M%S}{ext}"
        else:
            filename = f"encrypted_{algorithm}_{datetime.now():%Y%m%d_%H%M%S}.dat"
        file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
        metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
        with open(file_path, "wb") as f:
            f.write(file_data)
        metadata = {
            "file_id": file_id,
            "filename": filename,
            "algorithm": algorithm,
            "params": params,
            "original_filename": original_filename,
            "file_size": len(file_data),
            "created_at": datetime.now().isoformat(),
            "file_exists": True,
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        return file_id

    def get_encrypted_file(self, file_id: str) -> Optional[bytes]:
        path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        return None

    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.metadata_dir, f"{file_id}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def list_files(self) -> List[Dict[str, Any]]:
        files = []
        for fname in os.listdir(self.metadata_dir):
            if fname.endswith(".json"):
                file_id = fname[:-5]
                info = self.get_file_info(file_id)
                if info:
                    info["file_exists"] = os.path.exists(
                        os.path.join(self.encrypted_dir, f"{file_id}.enc")
                    )
                    files.append(info)
        return sorted(files, key=lambda x: x["created_at"], reverse=True)

    def delete_file(self, file_id: str) -> bool:
        try:
            for path in [
                os.path.join(self.encrypted_dir, f"{file_id}.enc"),
                os.path.join(self.metadata_dir, f"{file_id}.json"),
            ]:
                if os.path.exists(path):
                    os.remove(path)
            return True
        except Exception:
            return False

    def cleanup_orphaned_files(self) -> int:
        cleaned_count = 0
        for fname in os.listdir(self.encrypted_dir):
            if fname.endswith(".enc"):
                file_id = fname[:-4]
                metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
                if not os.path.exists(metadata_path):
                    try:
                        os.remove(os.path.join(self.encrypted_dir, fname))
                        cleaned_count += 1
                    except Exception:
                        pass
        for fname in os.listdir(self.metadata_dir):
            if fname.endswith(".json"):
                file_id = fname[:-5]
                file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
                if not os.path.exists(file_path):
                    try:
                        os.remove(os.path.join(self.metadata_dir, fname))
                        cleaned_count += 1
                    except Exception:
                        pass
        return cleaned_count

    def get_storage_info(self) -> Dict[str, Any]:
        files = self.list_files()
        total_size = sum(f["file_size"] for f in files)
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "encrypted_dir": self.encrypted_dir,
            "metadata_dir": self.metadata_dir,
        }

    def export_file(self, file_id: str, export_path: str) -> bool:
        try:
            data = self.get_encrypted_file(file_id)
            if data:
                with open(export_path, "wb") as f:
                    f.write(data)
                return True
            return False
        except Exception:
            return False

    def import_file(
        self,
        file_path: str,
        algorithm: str,
        params: Dict[str, Any],
        original_filename: Optional[str] = None,
    ) -> str:
        with open(file_path, "rb") as f:
            data = f.read()
        return self.save_encrypted_file(data, algorithm, params, original_filename)


file_manager = FileManager()
