import json
import os

class Settings:
    def __init__(self):
        self.config_file = os.path.abspath("config/settings.json")
        self.default_settings = {
            "nginx_path": os.path.abspath("C:/nginx/nginx.exe"),
            "config_path": os.path.abspath("C:/nginx/conf/nginx.conf"),
            "last_backup_dir": os.path.abspath("backups"),
            "auto_reload": True
        }
        self.settings = self.load_settings()

    def load_settings(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    # 确保所有路径都是绝对路径
                    for key in ['nginx_path', 'config_path', 'last_backup_dir']:
                        if key in loaded_settings:
                            loaded_settings[key] = os.path.abspath(loaded_settings[key])
                    return {**self.default_settings, **loaded_settings}
        except Exception as e:
            print(f"加载配置文件失败: {e}")
        return self.default_settings.copy()

    def save_settings(self):
        """保存配置"""
        try:
            # 确保配置目录存在
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            # 确保所有路径都是绝对路径
            settings_to_save = self.settings.copy()
            for key in ['nginx_path', 'config_path', 'last_backup_dir']:
                if key in settings_to_save:
                    settings_to_save[key] = os.path.abspath(settings_to_save[key])
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置文件失败: {e}")

    def get(self, key, default=None):
        """获取配置项"""
        value = self.settings.get(key, default)
        # 对路径类型的配置项确保返回绝对路径
        if key in ['nginx_path', 'config_path', 'last_backup_dir'] and value:
            return os.path.abspath(value)
        return value

    def set(self, key, value):
        """设置配置项"""
        # 对路径类型的配置项转换为绝对路径
        if key in ['nginx_path', 'config_path', 'last_backup_dir'] and value:
            value = os.path.abspath(value)
        self.settings[key] = value
        self.save_settings()

    def validate_paths(self):
        """验证所有路径的有效性"""
        validation_results = {
            "nginx_path": os.path.exists(self.get("nginx_path")),
            "config_path": os.path.exists(self.get("config_path")),
            "backup_dir": os.path.exists(self.get("last_backup_dir"))
        }
        return validation_results 