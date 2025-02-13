from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QLineEdit, QPushButton, QFileDialog)
from PyQt6.QtCore import Qt

class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("设置")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)

        # Nginx路径设置
        nginx_layout = QHBoxLayout()
        self.nginx_path_edit = QLineEdit(self.settings.get("nginx_path", ""))
        nginx_layout.addWidget(QLabel("Nginx路径:"))
        nginx_layout.addWidget(self.nginx_path_edit)
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.browse_nginx)
        nginx_layout.addWidget(browse_btn)
        layout.addLayout(nginx_layout)

        # 配置文件路径设置
        config_layout = QHBoxLayout()
        self.config_path_edit = QLineEdit(self.settings.get("config_path", ""))
        config_layout.addWidget(QLabel("配置文件:"))
        config_layout.addWidget(self.config_path_edit)
        config_browse_btn = QPushButton("浏览...")
        config_browse_btn.clicked.connect(self.browse_config)
        config_layout.addWidget(config_browse_btn)
        layout.addLayout(config_layout)

        # 按钮
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        cancel_btn = QPushButton("取消")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def browse_nginx(self):
        """浏览选择Nginx可执行文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择Nginx可执行文件",
            "",
            "Nginx (nginx.exe);;所有文件 (*.*)"
        )
        if file_path:
            self.nginx_path_edit.setText(file_path)

    def browse_config(self):
        """浏览选择配置文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择Nginx配置文件",
            "",
            "配置文件 (*.conf);;所有文件 (*.*)"
        )
        if file_path:
            self.config_path_edit.setText(file_path)

    def save_settings(self):
        """保存设置"""
        self.settings.set("nginx_path", self.nginx_path_edit.text())
        self.settings.set("config_path", self.config_path_edit.text())
        self.accept() 