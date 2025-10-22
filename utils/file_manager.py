import os
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import shutil


class FileManager:
    def __init__(self, base_dir: str = "EncryptedFiles"):
        self.base_dir = base_dir
        self.encrypted_dir = os.path.join(base_dir, "encrypted")
        self.metadata_dir = os.path.join(base_dir, "metadata")
        
        self._create_directories()
    
    def _create_directories(self):
        """Gerekli klasörleri oluşturur"""
        for directory in [self.base_dir, self.encrypted_dir, self.metadata_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def save_encrypted_file(self, file_data: bytes, algorithm: str, params: Dict[str, Any], 
                           original_filename: Optional[str] = None) -> str:
        file_id = str(uuid.uuid4())
        
        if original_filename:
            name, ext = os.path.splitext(original_filename)
            filename = f"{name}_{algorithm}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        else:
            filename = f"encrypted_{algorithm}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.dat"
        
        file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
        metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        metadata = {
            'file_id': file_id,
            'filename': filename,
            'algorithm': algorithm,
            'params': params,
            'original_filename': original_filename,
            'file_size': len(file_data),
            'created_at': datetime.now().isoformat(),
            'file_exists': True
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        return file_id
    
    def get_encrypted_file(self, file_id: str) -> Optional[bytes]:
        file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
        
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                return f.read()
        
        return None
    
    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
        
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        return None
    
    def list_files(self) -> List[Dict[str, Any]]:
        files = []
        
        for filename in os.listdir(self.metadata_dir):
            if filename.endswith('.json'):
                file_id = filename[:-5]  
                file_info = self.get_file_info(file_id)
                
                if file_info:
                    file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
                    file_info['file_exists'] = os.path.exists(file_path)
                    files.append(file_info)
        
        files.sort(key=lambda x: x['created_at'], reverse=True)
        
        return files
    
    def delete_file(self, file_id: str) -> bool:
        try:
            file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
            metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
            
            if os.path.exists(file_path):
                os.remove(file_path)
            
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            
            return True
            
        except Exception:
            return False
    
    def cleanup_orphaned_files(self) -> int:
        cleaned_count = 0
        
        for filename in os.listdir(self.encrypted_dir):
            if filename.endswith('.enc'):
                file_id = filename[:-4]  
                metadata_path = os.path.join(self.metadata_dir, f"{file_id}.json")
                
                if not os.path.exists(metadata_path):
                    file_path = os.path.join(self.encrypted_dir, filename)
                    try:
                        os.remove(file_path)
                        cleaned_count += 1
                    except Exception:
                        pass
        
        for filename in os.listdir(self.metadata_dir):
            if filename.endswith('.json'):
                file_id = filename[:-5]  
                file_path = os.path.join(self.encrypted_dir, f"{file_id}.enc")
                
                if not os.path.exists(file_path):
                    metadata_path = os.path.join(self.metadata_dir, filename)
                    try:
                        os.remove(metadata_path)
                        cleaned_count += 1
                    except Exception:
                        pass
        
        return cleaned_count
    
    def get_storage_info(self) -> Dict[str, Any]:
        files = self.list_files()
        total_files = len(files)
        total_size = sum(f['file_size'] for f in files)
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'encrypted_dir': self.encrypted_dir,
            'metadata_dir': self.metadata_dir
        }
    
    def export_file(self, file_id: str, export_path: str) -> bool:
        try:
            file_data = self.get_encrypted_file(file_id)
            if file_data:
                with open(export_path, 'wb') as f:
                    f.write(file_data)
                return True
            return False
        except Exception:
            return False
    
    def import_file(self, file_path: str, algorithm: str, params: Dict[str, Any], 
                   original_filename: Optional[str] = None) -> str:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        return self.save_encrypted_file(file_data, algorithm, params, original_filename)


file_manager = FileManager()
