import os
import shutil
from datetime import datetime

class FileUtils:
    @staticmethod
    def backup_file(file_path, backup_dir="backups"):
        """创建文件备份"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
            
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        backup_path = os.path.join(
            backup_dir, 
            f"{filename}.{timestamp}.bak"
        )
        
        shutil.copy2(file_path, backup_path)
        return backup_path
    
    @staticmethod
    def ensure_dir(path):
        """确保目录存在"""
        if not os.path.exists(path):
            os.makedirs(path) 