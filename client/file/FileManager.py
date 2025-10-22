"""
Dosya yönetimi sınıfı - Dosya açma, kaydetme ve format kontrolü
"""
import os
import json
from typing import Optional, Dict, Any, List
from shared.utils import FileUtils, Logger


class FileManager:
    
    def __init__(self, base_path: str = "EncryptedFiles"):
        """
        Args:
            base_path: Dosyaların saklanacağı ana dizin
        """
        self.base_path = base_path
        self.encrypted_path = os.path.join(base_path, "encrypted")
        self.metadata_path = os.path.join(base_path, "metadata")
        
        self._create_directories()
    
    def _create_directories(self):
        for path in [self.base_path, self.encrypted_path, self.metadata_path]:
            os.makedirs(path, exist_ok=True)
    
    def save_file(self, data: bytes, filename: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Dosyayı kaydeder
        
        Args:
            data: Kaydedilecek veri
            filename: Dosya adı
            metadata: Ek bilgiler (algorithm, key, timestamp vb.)
        
        Returns:
            Başarı durumu
        """
        try:
            if metadata is None:
                metadata = {}
            
            file_path = os.path.join(self.encrypted_path, filename)
            
            with open(file_path, 'wb') as f:
                f.write(data)
            
            metadata_filename = f"{os.path.splitext(filename)[0]}_metadata.json"
            metadata_path = os.path.join(self.metadata_path, metadata_filename)
            
            metadata.update({
                'filename': filename,
                'file_size': len(data),
                'file_type': FileUtils.get_file_type(filename),
                'file_hash': FileUtils.calculate_file_hash(file_path)
            })
            
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            Logger.info(f"Dosya kaydedildi: {filename}", "FileManager")
            return True
            
        except Exception as e:
            Logger.error(f"Dosya kaydetme hatası: {str(e)}", "FileManager")
            return False
    
    def load_file(self, filename: str) -> Optional[bytes]:
        """
        Dosyayı yükler
        
        Args:
            filename: Yüklenecek dosya adı
        
        Returns:
            Dosya verisi veya None
        """
        try:
            file_path = os.path.join(self.encrypted_path, filename)
            
            if not os.path.exists(file_path):
                Logger.warning(f"Dosya bulunamadı: {filename}", "FileManager")
                return None
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            Logger.info(f"Dosya yüklendi: {filename}", "FileManager")
            return data
            
        except Exception as e:
            Logger.error(f"Dosya yükleme hatası: {str(e)}", "FileManager")
            return None
    
    def load_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """
        Dosya metadata'sını yükler
        
        Args:
            filename: Metadata'sı yüklenecek dosya adı
        
        Returns:
            Metadata dictionary veya None
        """
        try:
            metadata_filename = f"{os.path.splitext(filename)[0]}_metadata.json"
            metadata_path = os.path.join(self.metadata_path, metadata_filename)
            
            if not os.path.exists(metadata_path):
                Logger.warning(f"Metadata bulunamadı: {filename}", "FileManager")
                return None
            
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            return metadata
            
        except Exception as e:
            Logger.error(f"Metadata yükleme hatası: {str(e)}", "FileManager")
            return None
    
    def list_files(self) -> List[Dict[str, Any]]:
        """
        Kayıtlı dosyaları listeler
        
        Returns:
            Dosya bilgileri listesi
        """
        files = []
        
        try:
            for filename in os.listdir(self.encrypted_path):
                if os.path.isfile(os.path.join(self.encrypted_path, filename)):
                    metadata = self.load_metadata(filename)
                    file_info = {
                        'filename': filename,
                        'size': os.path.getsize(os.path.join(self.encrypted_path, filename)),
                        'metadata': metadata
                    }
                    files.append(file_info)
            
            Logger.info(f"{len(files)} dosya listelendi", "FileManager")
            return files
            
        except Exception as e:
            Logger.error(f"Dosya listeleme hatası: {str(e)}", "FileManager")
            return []
    
    def delete_file(self, filename: str) -> bool:
        """
        Dosyayı siler
        
        Args:
            filename: Silinecek dosya adı
        
        Returns:
            Başarı durumu
        """
        try:
            file_path = os.path.join(self.encrypted_path, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            
            metadata_filename = f"{os.path.splitext(filename)[0]}_metadata.json"
            metadata_path = os.path.join(self.metadata_path, metadata_filename)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            
            Logger.info(f"Dosya silindi: {filename}", "FileManager")
            return True
            
        except Exception as e:
            Logger.error(f"Dosya silme hatası: {str(e)}", "FileManager")
            return False
    
    def get_file_info(self, filename: str) -> Optional[Dict[str, Any]]:
        """
        Dosya hakkında detaylı bilgi döndürür
        
        Args:
            filename: Bilgi alınacak dosya adı
        
        Returns:
            Dosya bilgileri veya None
        """
        try:
            file_path = os.path.join(self.encrypted_path, filename)
            
            if not os.path.exists(file_path):
                return None
            
            metadata = self.load_metadata(filename)
            
            file_info = {
                'filename': filename,
                'size': os.path.getsize(file_path),
                'file_type': FileUtils.get_file_type(filename),
                'is_supported': FileUtils.is_supported_format(filename),
                'metadata': metadata
            }
            
            return file_info
            
        except Exception as e:
            Logger.error(f"Dosya bilgi alma hatası: {str(e)}", "FileManager")
            return None

