from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                           QPushButton, QLabel, QStatusBar, QMessageBox, QMenuBar, QMenu)
from PyQt6.QtCore import Qt, QTimer
from .config_manager import ConfigManager
from core.nginx_controller import NginxManager
from config.settings import Settings
from .settings_dialog import SettingsDialog

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = Settings()
        self.nginx = NginxManager(self.settings.get("nginx_path"))
        self.init_ui()
        # 立即检查Nginx状态
        self.check_nginx_status()
        
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("Nginx 管理工具")
        self.setGeometry(100, 100, 1000, 600)
        
        # 创建中心部件和主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # 创建菜单栏
        self.create_menu_bar()
        
        # 创建选项卡
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # 初始化各个标签页
        self.init_status_tab()
        self.init_config_tab()
        self.init_ssl_tab()
        
        # 创建状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("正在检查Nginx状态...")
        self.status_bar.addWidget(self.status_label)
        
        # 定时更新状态
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_nginx_status)
        self.status_timer.start(5000)  # 每5秒更新一次

    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu("文件")
        
        # 设置菜单项
        settings_action = file_menu.addAction("设置")
        settings_action.triggered.connect(self.show_settings)
        
        # 退出菜单项
        exit_action = file_menu.addAction("退出")
        exit_action.triggered.connect(self.close)
        
    def init_status_tab(self):
        """初始化状态标签页"""
        status_tab = QWidget()
        layout = QVBoxLayout(status_tab)
        
        # Nginx控制按钮
        self.start_btn = QPushButton("启动")
        self.stop_btn = QPushButton("停止")
        self.reload_btn = QPushButton("重载")
        
        # 绑定事件
        self.start_btn.clicked.connect(self.start_nginx)
        self.stop_btn.clicked.connect(self.stop_nginx)
        self.reload_btn.clicked.connect(self.reload_nginx)
        
        # 添加到布局
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.reload_btn)
        layout.addStretch()
        
        self.tabs.addTab(status_tab, "状态")
        
    def init_config_tab(self):
        """初始化配置管理标签页"""
        config_tab = QWidget()
        layout = QVBoxLayout(config_tab)
        
        # 使用ConfigManager替代ConfigEditor
        self.config_manager = ConfigManager()
        layout.addWidget(self.config_manager)
        
        # 加载配置文件
        config_path = self.settings.get("config_path")
        if config_path:
            self.config_manager.load_config(config_path)
            
        self.tabs.addTab(config_tab, "配置管理")
        
    def init_ssl_tab(self):
        """初始化SSL证书标签页"""
        ssl_tab = QWidget()
        layout = QVBoxLayout(ssl_tab)
        
        # TODO: 添加SSL证书管理界面
        layout.addWidget(QLabel("SSL证书管理（开发中）"))
        
        self.tabs.addTab(ssl_tab, "SSL证书")
        
    def check_nginx_status(self):
        """初始检查Nginx状态"""
        try:
            is_running = self.nginx.is_running()
            self.update_ui_status(is_running)
            
            # 如果Nginx正在运行，尝试获取版本信息
            if is_running:
                try:
                    version = self.nginx.get_version()
                    self.status_label.setText(f"Nginx {version} 正在运行")
                except:
                    self.status_label.setText("Nginx 正在运行")
            else:
                self.status_label.setText("Nginx 未运行")
                
        except Exception as e:
            self.status_label.setText(f"Nginx状态检查失败: {str(e)}")
            QMessageBox.warning(
                self,
                "警告",
                f"Nginx状态检查失败: {str(e)}\n请检查Nginx路径设置是否正确。"
            )

    def update_ui_status(self, is_running):
        """更新UI状态"""
        # 更新按钮状态
        self.start_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        self.reload_btn.setEnabled(is_running)
        
        # 更新按钮样式
        self.start_btn.setStyleSheet(
            "background-color: #4CAF50;" if not is_running else "background-color: #cccccc;"
        )
        self.stop_btn.setStyleSheet(
            "background-color: #f44336;" if is_running else "background-color: #cccccc;"
        )
        self.reload_btn.setStyleSheet(
            "background-color: #2196F3;" if is_running else "background-color: #cccccc;"
        )

    def update_nginx_status(self):
        """定时更新Nginx状态"""
        try:
            is_running = self.nginx.is_running()
            self.update_ui_status(is_running)
            
            # 只在状态发生变化时更新状态栏文本
            current_status = "运行中" if is_running else "已停止"
            if self.status_label.text() != f"Nginx状态: {current_status}":
                self.status_label.setText(f"Nginx状态: {current_status}")
                
        except Exception as e:
            self.status_label.setText(f"状态更新失败: {str(e)}")

    def start_nginx(self):
        """启动Nginx"""
        try:
            if self.nginx.start():
                self.status_label.setText("Nginx已启动")
            else:
                QMessageBox.warning(self, "警告", "Nginx启动失败或已在运行")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"启动Nginx时发生错误: {str(e)}")
            
    def stop_nginx(self):
        """停止Nginx"""
        try:
            if self.nginx.stop():
                self.status_label.setText("Nginx已停止")
            else:
                QMessageBox.warning(self, "警告", "Nginx停止失败或未在运行")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"停止Nginx时发生错误: {str(e)}")
            
    def reload_nginx(self):
        """重载Nginx配置"""
        try:
            if self.nginx.reload():
                self.status_label.setText("Nginx配置已重载")
            else:
                QMessageBox.warning(self, "警告", "Nginx重载失败")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"重载Nginx时发生错误: {str(e)}")
            
    def show_settings(self):
        """显示设置对话框"""
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec():
            # 更新Nginx管理器的路径
            self.nginx = NginxManager(self.settings.get("nginx_path"))
            # 如果配置文件路径已更改，重新加载配置
            if hasattr(self, 'config_manager'):
                self.config_manager.load_config(self.settings.get("config_path")) 