from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QTextEdit, QMessageBox)
from PyQt6.QtCore import Qt
from core.config_parser import NginxConfigParser
from utils.file_utils import FileUtils
import os
from config.settings import Settings
import subprocess

class ConfigEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parser = NginxConfigParser()
        self.current_config_path = None
        self.file_utils = FileUtils()
        self.settings = Settings()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 创建编辑器
        self.editor = QTextEdit()
        self.editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        
        # 工具栏
        toolbar = QHBoxLayout()
        self.save_btn = QPushButton("保存")
        self.test_btn = QPushButton("测试配置")
        self.reload_btn = QPushButton("重新加载")
        
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.test_btn)
        toolbar.addWidget(self.reload_btn)
        toolbar.addStretch()
        
        # 绑定事件
        self.save_btn.clicked.connect(self.save_config)
        self.test_btn.clicked.connect(self.test_config)
        self.reload_btn.clicked.connect(self.reload_config)
        
        layout.addLayout(toolbar)
        layout.addWidget(self.editor)
        self.setLayout(layout)
    
    def load_config(self, config_path):
        """加载配置文件"""
        try:
            self.current_config_path = config_path
            if not os.path.exists(config_path):
                QMessageBox.warning(self, "警告", f"配置文件不存在: {config_path}")
                return
                
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.editor.setText(content)
                
            # 验证配置文件语法
            is_valid, error = self.parser.validate(content)
            if not is_valid:
                QMessageBox.warning(self, "配置语法警告", f"配置文件可能存在语法问题：\n{error}")
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"配置文件加载失败: {str(e)}")
    
    def save_config(self):
        """保存配置文件"""
        if not self.current_config_path:
            QMessageBox.warning(self, "警告", "没有指定配置文件路径")
            return
            
        try:
            # 获取编辑器内容
            content = self.editor.toPlainText()
            
            # 验证配置语法
            is_valid, error = self.parser.validate(content)
            if not is_valid:
                result = QMessageBox.warning(
                    self,
                    "配置语法警告",
                    f"配置文件可能存在语法问题：\n{error}\n是否继续保存？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if result == QMessageBox.StandardButton.No:
                    return
            
            # 创建备份
            backup_path = self.file_utils.backup_file(self.current_config_path)
            
            # 保存文件
            with open(self.current_config_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            QMessageBox.information(
                self,
                "成功",
                f"配置已保存\n备份文件：{backup_path}"
            )
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"配置保存失败: {str(e)}")
    
    def test_config(self):
        """测试配置文件"""
        if not self.current_config_path:
            QMessageBox.warning(self, "警告", "没有指定配置文件路径")
            return
            
        try:
            # 获取编辑器内容
            content = self.editor.toPlainText()
            
            # 获取nginx安装目录
            nginx_path = self.settings.get("nginx_path")
            nginx_dir = os.path.dirname(nginx_path)
            
            # 使用原始配置文件的相对路径创建临时文件
            original_config_name = os.path.basename(self.current_config_path)
            temp_config = os.path.join(nginx_dir, "conf", f"temp_{original_config_name}")
            
            try:
                # 确保临时文件目录存在
                os.makedirs(os.path.dirname(temp_config), exist_ok=True)
                
                # 保存到临时文件
                with open(temp_config, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # 使用nginx -t测试配置
                from core.nginx_controller import NginxManager
                nginx = NginxManager(nginx_path)
                
                # 使用临时配置文件进行测试
                test_result = subprocess.run(
                    [nginx_path, "-t", "-c", temp_config],
                    capture_output=True,
                    text=True,
                    cwd=nginx_dir  # 设置工作目录为nginx安装目录
                )
                
                if test_result.returncode == 0:
                    QMessageBox.information(self, "成功", "配置文件语法正确")
                else:
                    QMessageBox.warning(
                        self,
                        "警告",
                        f"配置文件存在问题：\n{test_result.stderr}"
                    )
                    
            finally:
                # 清理临时文件
                if os.path.exists(temp_config):
                    try:
                        os.remove(temp_config)
                    except:
                        pass
                        
        except Exception as e:
            QMessageBox.critical(self, "错误", f"配置测试失败: {str(e)}")
            
    def reload_config(self):
        """重新加载配置"""
        try:
            # 检查是否有未保存的更改
            if self.current_config_path:
                result = QMessageBox.question(
                    self,
                    "确认重载",
                    "重新加载将丢失未保存的更改，是否继续？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                
                if result == QMessageBox.StandardButton.No:
                    return
                
                # 直接从文件重新加载配置
                self.load_config(self.current_config_path)
            
            # 获取nginx路径和工作目录
            nginx_path = self.settings.get("nginx_path")
            nginx_dir = os.path.dirname(nginx_path)
            
            # 先测试配置
            test_result = subprocess.run(
                [nginx_path, "-t"],
                capture_output=True,
                text=True,
                cwd=nginx_dir
            )
            
            if test_result.returncode != 0:
                QMessageBox.critical(
                    self,
                    "错误",
                    f"配置测试失败，无法重载：\n{test_result.stderr}"
                )
                return
            
            # 重载nginx配置
            reload_result = subprocess.run(
                [nginx_path, "-s", "reload"],
                capture_output=True,
                text=True,
                cwd=nginx_dir
            )
            
            if reload_result.returncode == 0:
                QMessageBox.information(
                    self,
                    "成功",
                    "Nginx配置已重新加载"
                )
            else:
                QMessageBox.warning(
                    self,
                    "警告",
                    f"Nginx配置重载失败：\n{reload_result.stderr}"
                )
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "错误",
                f"配置重载失败: {str(e)}"
            ) 