from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                           QPushButton, QTreeWidget, QTreeWidgetItem, 
                           QTextEdit, QMessageBox, QMenu, QInputDialog,
                           QDialog, QComboBox, QLabel, QDialogButtonBox,
                           QGroupBox, QCheckBox, QLineEdit, QFormLayout)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QFont, QColor
from core.config_parser import NginxConfigParser
from pyparsing import ParseResults
import os

class DirectiveDialog(QDialog):
    """指令添加对话框"""
    def __init__(self, parent=None, context_info=None):
        super().__init__(parent)
        self.setWindowTitle("添加指令")
        self.context_info = context_info or {}
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 指令名称
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("指令名称:"))
        self.name_input = QComboBox()
        self.name_input.setEditable(True)
        # 添加常用指令建议
        common_directives = [
            "listen",
            "server_name",
            "root",
            "index",
            "proxy_pass",
            "proxy_set_header",
            "fastcgi_pass",
            "access_log",
            "error_log",
            "ssl_certificate",
            "ssl_certificate_key",
            "return",
            "rewrite",
            "add_header"
        ]
        self.name_input.addItems(common_directives)
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)
        
        # 指令值
        value_layout = QHBoxLayout()
        value_layout.addWidget(QLabel("指令值:"))
        self.value_input = QLineEdit()
        value_layout.addWidget(self.value_input)
        layout.addLayout(value_layout)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_directive(self):
        """获取指令内容"""
        name = self.name_input.currentText().strip()
        value = self.value_input.text().strip()
        if name and value:
            return f"{name} {value};"
        return None

class BlockDialog(QDialog):
    """块编辑对话框"""
    def __init__(self, parent=None, context_info=None):
        super().__init__(parent)
        self.setWindowTitle("添加配置块")
        self.context_info = context_info or {}
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 块类型选择
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("块类型:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["location", "server", "upstream", "if"])
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        type_layout.addWidget(self.type_combo)
        layout.addLayout(type_layout)
        
        # 常用指令组
        self.directives_group = QGroupBox("常用指令")
        directives_layout = QVBoxLayout()
        
        # Server块指令
        self.server_widgets = {
            "listen": self.create_directive_input("监听端口", "80"),
            "server_name": self.create_directive_input("服务器名称", "example.com"),
            "root": self.create_directive_input("根目录", "/var/www/html"),
            "index": self.create_directive_input("默认页面", "index.html index.htm"),
            "ssl_certificate": self.create_directive_input("SSL证书路径", ""),
            "ssl_certificate_key": self.create_directive_input("SSL密钥路径", "")
        }
        
        # Location块指令
        self.location_widgets = {
            "root": self.create_directive_input("根目录", "/var/www/html"),
            "proxy_pass": self.create_directive_input("代理地址", "http://backend"),
            "proxy_set_header": self.create_directive_input("代理头", "Host $host"),
            "try_files": self.create_directive_input("文件查找", "$uri $uri/ /index.html")
        }
        
        # Upstream块指令
        self.upstream_widgets = {
            "server": self.create_directive_input("服务器地址", "127.0.0.1:8080"),
            "ip_hash": QCheckBox("启用IP哈希"),
            "least_conn": QCheckBox("最小连接数")
        }
        
        # 添加所有指令组件
        for widgets in [self.server_widgets, self.location_widgets, self.upstream_widgets]:
            for name, widget in widgets.items():
                container = QHBoxLayout()
                container.addWidget(QLabel(f"{name}:"))
                container.addWidget(widget)
                directives_layout.addLayout(container)
                widget.hide()  # 初始隐藏所有指令
                
        self.directives_group.setLayout(directives_layout)
        layout.addWidget(self.directives_group)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # 初始显示server块的指令
        self.on_type_changed("server")
        
    def create_directive_input(self, placeholder, default=""):
        """创建指令输入框"""
        input_widget = QLineEdit()
        input_widget.setPlaceholderText(placeholder)
        input_widget.setText(default)
        return input_widget
        
    def on_type_changed(self, block_type):
        """处理块类型改变"""
        # 隐藏所有指令
        for widgets in [self.server_widgets, self.location_widgets, self.upstream_widgets]:
            for widget in widgets.values():
                widget.hide()
        
        # 显示对应类型的指令
        if block_type == "server":
            for widget in self.server_widgets.values():
                widget.show()
        elif block_type == "location":
            for widget in self.location_widgets.values():
                widget.show()
        elif block_type == "upstream":
            for widget in self.upstream_widgets.values():
                widget.show()
                
    def get_block_content(self):
        """获取块配置内容"""
        block_type = self.type_combo.currentText()
        content = []
        
        if block_type == "server":
            widgets = self.server_widgets
        elif block_type == "location":
            widgets = self.location_widgets
        elif block_type == "upstream":
            widgets = self.upstream_widgets
        else:
            return ""
            
        # 添加指令
        for name, widget in widgets.items():
            if isinstance(widget, QLineEdit):
                value = widget.text().strip()
                if value:
                    content.append(f"    {name} {value};")
            elif isinstance(widget, QCheckBox) and widget.isChecked():
                content.append(f"    {name};")
                
        # 组装块内容
        return f"{block_type} {{\n" + "\n".join(content) + "\n}}"

class ServerConfigDialog(QDialog):
    """Server配置对话框"""
    def __init__(self, parent=None, existing_config=None):
        super().__init__(parent)
        self.setWindowTitle("Server配置")
        self.existing_config = existing_config
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 基本配置
        basic_group = QGroupBox("基本配置")
        basic_layout = QFormLayout()
        
        self.listen_input = QLineEdit()
        self.listen_input.setPlaceholderText("80")
        basic_layout.addRow("监听端口:", self.listen_input)
        
        self.server_name_input = QLineEdit()
        self.server_name_input.setPlaceholderText("example.com")
        basic_layout.addRow("服务器名称:", self.server_name_input)
        
        self.root_input = QLineEdit()
        self.root_input.setPlaceholderText("/var/www/html")
        basic_layout.addRow("根目录:", self.root_input)
        
        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)
        
        # SSL配置
        ssl_group = QGroupBox("SSL配置")
        ssl_layout = QFormLayout()
        
        self.ssl_enable = QCheckBox("启用SSL")
        self.ssl_enable.stateChanged.connect(self.toggle_ssl_inputs)
        ssl_layout.addRow(self.ssl_enable)
        
        self.ssl_cert_input = QLineEdit()
        self.ssl_key_input = QLineEdit()
        ssl_layout.addRow("SSL证书:", self.ssl_cert_input)
        ssl_layout.addRow("SSL密钥:", self.ssl_key_input)
        
        ssl_group.setLayout(ssl_layout)
        layout.addWidget(ssl_group)
        
        # 代理配置
        proxy_group = QGroupBox("代理配置")
        proxy_layout = QFormLayout()
        
        self.proxy_enable = QCheckBox("启用代理")
        self.proxy_enable.stateChanged.connect(self.toggle_proxy_inputs)
        proxy_layout.addRow(self.proxy_enable)
        
        self.proxy_pass_input = QLineEdit()
        self.proxy_pass_input.setPlaceholderText("http://backend")
        proxy_layout.addRow("代理地址:", self.proxy_pass_input)
        
        self.proxy_headers = QTextEdit()
        self.proxy_headers.setPlaceholderText("Host $host\nX-Real-IP $remote_addr")
        self.proxy_headers.setMaximumHeight(100)
        proxy_layout.addRow("代理头:", self.proxy_headers)
        
        proxy_group.setLayout(proxy_layout)
        layout.addWidget(proxy_group)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # 初始化状态
        self.toggle_ssl_inputs()
        self.toggle_proxy_inputs()
        
        if self.existing_config:
            self.load_existing_config()
            
    def toggle_ssl_inputs(self):
        """切换SSL相关输入框的启用状态"""
        enabled = self.ssl_enable.isChecked()
        self.ssl_cert_input.setEnabled(enabled)
        self.ssl_key_input.setEnabled(enabled)
        
    def toggle_proxy_inputs(self):
        """切换代理相关输入框的启用状态"""
        enabled = self.proxy_enable.isChecked()
        self.proxy_pass_input.setEnabled(enabled)
        self.proxy_headers.setEnabled(enabled)
        
    def load_existing_config(self):
        """加载现有配置"""
        if not self.existing_config:
            return
            
        # TODO: 从现有配置中加载值
        
    def get_config(self):
        """获取配置内容"""
        config = []
        
        # 添加server块
        config.append("server {")
        
        # 基本配置
        if self.listen_input.text():
            config.append(f"    listen {self.listen_input.text()};")
        if self.server_name_input.text():
            config.append(f"    server_name {self.server_name_input.text()};")
        if self.root_input.text():
            config.append(f"    root {self.root_input.text()};")
            
        # SSL配置
        if self.ssl_enable.isChecked():
            if self.ssl_cert_input.text():
                config.append(f"    ssl_certificate {self.ssl_cert_input.text()};")
            if self.ssl_key_input.text():
                config.append(f"    ssl_certificate_key {self.ssl_key_input.text()};")
                
        # 代理配置
        if self.proxy_enable.isChecked():
            if self.proxy_pass_input.text():
                config.append("\n    location / {")
                config.append(f"        proxy_pass {self.proxy_pass_input.text()};")
                
                # 添加代理头
                for header in self.proxy_headers.toPlainText().split('\n'):
                    if header.strip():
                        config.append(f"        proxy_set_header {header};")
                        
                config.append("    }")
                
        config.append("}")
        return "\n".join(config)

class TemplateDialog(QDialog):
    """配置模板对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("配置模板")
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 模板类型选择
        self.template_combo = QComboBox()
        self.template_combo.addItems([
            "静态网站",
            "反向代理",
            "负载均衡",
            "SSL配置",
            "PHP站点",
            "WordPress",
            "自定义"
        ])
        self.template_combo.currentTextChanged.connect(self.on_template_changed)
        layout.addWidget(self.template_combo)
        
        # 模板预览
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        layout.addWidget(self.preview)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # 显示初始模板
        self.on_template_changed(self.template_combo.currentText())
        
    def on_template_changed(self, template_name):
        """处理模板选择变化"""
        templates = {
            "静态网站": r"""server {
    listen 80;
    server_name example.com;
    root /var/www/html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }
}""",
            "反向代理": r"""server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}""",
            "负载均衡": r"""upstream backend {
    least_conn;  # 最小连接数算法
    server backend1.example.com:8080;
    server backend2.example.com:8080;
    server backend3.example.com:8080;
}

server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}""",
            "SSL配置": r"""server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # 现代配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
}""",
            "PHP站点": r"""server {
    listen 80;
    server_name example.com;
    root /var/www/html;
    index index.php index.html;
    
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}""",
            "WordPress": r"""server {
    listen 80;
    server_name example.com;
    root /var/www/wordpress;
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # WordPress安全设置
    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt { log_not_found off; access_log off; }
    location ~ /\. { deny all; }
    location ~* /(?:uploads|files)/.*\.php$ { deny all; }
    
    # 缓存设置
    location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
        expires max;
        log_not_found off;
    }
}""",
            "自定义": r"""server {
    listen 80;
    server_name example.com;
    
    # 在此添加自定义配置
}"""
        }
        
        self.preview.setText(templates.get(template_name, ""))

class ConfigManager(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parser = NginxConfigParser()
        self.current_config_path = None
        self.init_ui()
        
    def init_ui(self):
        """初始化UI"""
        layout = QHBoxLayout(self)
        
        # 创建分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # 左侧面板：配置树
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # 工具栏
        toolbar = QHBoxLayout()
        self.add_server_btn = QPushButton("添加Server")
        self.add_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.add_server_btn.clicked.connect(self.add_server_block)
        toolbar.addWidget(self.add_server_btn)
        
        self.add_template_btn = QPushButton("使用模板")
        self.add_template_btn.clicked.connect(self.use_template)
        toolbar.addWidget(self.add_template_btn)
        
        self.validate_btn = QPushButton("验证配置")
        self.validate_btn.clicked.connect(self.validate_config)
        toolbar.addWidget(self.validate_btn)
        
        self.export_btn = QPushButton("导出配置")
        self.export_btn.clicked.connect(self.export_config)
        toolbar.addWidget(self.export_btn)
        
        toolbar.addStretch()
        left_layout.addLayout(toolbar)
        
        # 配置树
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["配置项", "值"])
        self.tree.setColumnWidth(0, 200)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #ffffff;
            }
            QTreeWidget::item {
                height: 25px;
                padding: 2px;
            }
            QTreeWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976d2;
            }
        """)
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.tree)
        
        # 右侧面板：编辑器
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 编辑器工具栏
        editor_toolbar = QHBoxLayout()
        self.save_btn = QPushButton("保存")
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #1976d2;
            }
        """)
        self.save_btn.clicked.connect(self.save_current_block)
        editor_toolbar.addWidget(self.save_btn)
        editor_toolbar.addStretch()
        right_layout.addLayout(editor_toolbar)
        
        # 编辑器
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fafafa;
                padding: 5px;
            }
        """)
        right_layout.addWidget(self.editor)
        
        # 添加面板到分割器
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 700])
        
    def load_config(self, config_path):
        """加载配置文件"""
        try:
            self.current_config_path = config_path
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 解析配置
            self.parser.parse(content)
            
            # 更新配置树
            self.update_tree()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载配置文件失败: {str(e)}")
            
    def update_tree(self):
        """更新配置树"""
        # 保存当前展开状态和选中项
        expanded_paths = self._get_expanded_paths(self.tree.invisibleRootItem())
        current_item = self.tree.currentItem()
        current_path = []
        if current_item:
            temp_item = current_item
            while temp_item:
                current_path.insert(0, (temp_item.text(0), temp_item.text(1)))
                temp_item = temp_item.parent()
        
        # 清空并重建树
        self.tree.clear()
        root = self.create_tree_item(self.tree, "Nginx配置")
        
        def add_directives_to_item(parent_item, block):
            """将指令添加到树节点"""
            if not isinstance(block, (list, ParseResults)):
                return
            
            for item in block:
                if isinstance(item, ParseResults):
                    # 跳过注释
                    if item.getName() == "comment":
                        continue
                    
                    if len(item) > 0:
                        if isinstance(item[-1], ParseResults):
                            # 这是一个块
                            block_name = str(item[0])
                            block_args = " ".join(str(x) for x in item[1:-1]) if len(item) > 2 else ""
                            block_item = self.create_tree_item(
                                parent_item,
                                block_name,
                                block_args,
                                item
                            )
                            # 递归处理块内容
                            add_directives_to_item(block_item, item[-1])
                        else:
                            # 这是一个指令
                            directive_name = str(item[0])
                            directive_value = " ".join(str(x) for x in item[1:]) if len(item) > 1 else ""
                            self.create_tree_item(
                                parent_item,
                                directive_name,
                                directive_value,
                                item
                            )
        
        # 添加所有配置项到树
        if self.parser.config_tree:
            add_directives_to_item(root, self.parser.config_tree)
        
        # 恢复展开状态
        self._restore_expanded_paths(self.tree.invisibleRootItem(), expanded_paths)
        
        # 恢复选中状态
        if current_path:
            self._select_item_by_path(current_path)

    def _get_expanded_paths(self, item):
        """递归获取所有展开项的路径"""
        paths = set()
        
        def collect_paths(current_item, current_path):
            if current_item.isExpanded():
                paths.add("/".join(current_path))
            
            for i in range(current_item.childCount()):
                child = current_item.child(i)
                child_path = current_path + [child.text(0)]
                collect_paths(child, child_path)
        
        collect_paths(item, [])
        return paths

    def _restore_expanded_paths(self, item, expanded_paths):
        """递归恢复展开状态"""
        def restore_paths(current_item, current_path):
            path_str = "/".join(current_path)
            if path_str in expanded_paths:
                current_item.setExpanded(True)
            
            for i in range(current_item.childCount()):
                child = current_item.child(i)
                child_path = current_path + [child.text(0)]
                restore_paths(child, child_path)
        
        restore_paths(item, [])

    def create_tree_item(self, parent, name, value="", data=None):
        """创建树节点"""
        item = QTreeWidgetItem(parent)
        item.setText(0, str(name))
        item.setText(1, str(value))
        if data is not None:
            item.setData(0, Qt.ItemDataRole.UserRole, data)
        return item

    def get_full_block_path(self, item):
        """获取节点的完整路径"""
        path = []
        while item is not None:
            path.insert(0, item.text(0))
            item = item.parent()
        return " > ".join(path)

    def on_item_clicked(self, item, column):
        """处理树节点点击事件"""
        block_data = item.data(0, Qt.ItemDataRole.UserRole)
        if block_data:
            # 显示完整路径
            path = self.get_full_block_path(item)
            self.editor.setPlaceholderText(f"编辑: {path}")
            
            # 将配置块转换为文本
            if isinstance(block_data[-1], list):
                # 这是一个块
                block_text = self.parser.to_string(block_data)
            else:
                # 这是一个指令
                block_text = " ".join(str(x) for x in block_data) + ";"
            
            self.editor.setText(block_text)
        else:
            self.editor.clear()
            self.editor.setPlaceholderText("选择一个配置项进行编辑")

    def show_context_menu(self, pos):
        """显示上下文菜单"""
        item = self.tree.itemAt(pos)
        if item:
            menu = QMenu(self)
            data = item.data(0, Qt.ItemDataRole.UserRole)
            
            if isinstance(data, ParseResults):
                block_type = str(data[0]) if len(data) > 0 else ""
                
                if block_type == "server":
                    # 添加指令
                    add_action = menu.addAction("添加指令")
                    add_action.triggered.connect(lambda: self.add_directive_to_block(item))
                    
                    # 编辑和删除动作
                    menu.addSeparator()
                    edit_action = menu.addAction("编辑")
                    edit_action.triggered.connect(lambda: self.edit_block(item))
                    delete_action = menu.addAction("删除")
                    delete_action.triggered.connect(lambda: self.delete_block(item))
                elif block_type == "location":
                    edit_action = menu.addAction("编辑")
                    edit_action.triggered.connect(lambda: self.edit_block(item))
                    delete_action = menu.addAction("删除")
                    delete_action.triggered.connect(lambda: self.delete_block(item))
                else:
                    # 其他类型的块
                    edit_action = menu.addAction("编辑")
                    edit_action.triggered.connect(lambda: self.edit_block(item))
                    delete_action = menu.addAction("删除")
                    delete_action.triggered.connect(lambda: self.delete_block(item))
            else:
                # 普通指令
                edit_action = menu.addAction("编辑")
                edit_action.triggered.connect(lambda: self.edit_directive(item))
                delete_action = menu.addAction("删除")
                delete_action.triggered.connect(lambda: self.delete_directive(item))
            
            menu.exec(self.tree.viewport().mapToGlobal(pos))

    def add_server_block(self):
        """添加新的server块"""
        dialog = ServerConfigDialog(self)
        if dialog.exec():
            try:
                # 获取配置内容
                server_config = dialog.get_config()
                
                # 解析新的server块
                new_block = self.parser.parse_block(server_config)
                
                # 查找http块
                http_block = None
                if self.parser.config_tree:
                    for item in self.parser.config_tree:
                        if isinstance(item, ParseResults) and item[0] == 'http':
                            http_block = item
                            break
                            
                # 如果没有http块，创建一个
                if not http_block:
                    http_block = self.parser.parse_block("http {}")
                    self.parser.config_tree.append(http_block)
                    
                # 添加server块到http块
                http_block[-1].append(new_block)
                
                # 更新树视图
                self.update_tree()
                
                # 保存配置文件
                self.save_config()
                
                QMessageBox.information(self, "成功", "Server配置已添加")
                
            except Exception as e:
                QMessageBox.critical(self, "错误", f"添加Server配置失败: {str(e)}")

    def delete_server_block(self, item):
        """删除server块"""
        try:
            reply = QMessageBox.question(
                self,
                "确认删除",
                "确定要删除这个server块吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # 从配置中删除server块
                block_data = item.data(0, Qt.ItemDataRole.UserRole)
                self.parser.remove_block(block_data)
                
                # 更新树视图
                self.update_tree()
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"删除server块失败: {str(e)}")
            
    def clone_server_block(self, item):
        """克隆server块"""
        try:
            block_data = item.data(0, Qt.ItemDataRole.UserRole)
            if block_data:
                # 复制server块内容
                block_text = self.parser.to_string(block_data)
                
                # 添加到配置中
                self.parser.add_block("http", block_text)
                
                # 更新树视图
                self.update_tree()
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"克隆server块失败: {str(e)}")
            
    def save_current_block(self):
        """保存当前编辑的配置块"""
        try:
            # 获取当前选中的项
            current_item = self.tree.currentItem()
            if not current_item:
                return
                
            # 获取编辑器内容
            content = self.editor.toPlainText()
            
            # 更新配置
            block_data = current_item.data(0, Qt.ItemDataRole.UserRole)
            if block_data:
                self.parser.update_block(block_data, content)
                
                # 保存整个配置文件
                self.save_config()
                
                # 更新树视图
                self.update_tree()
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存配置块失败: {str(e)}")
            
    def add_directive_to_block(self, item):
        """向块中添加指令"""
        if not item or not item.parent():  # 检查item是否有效
            QMessageBox.warning(self, "警告", "无效的配置项")
            return
        
        dialog = DirectiveDialog(self)
        if dialog.exec():
            try:
                directive_str = dialog.get_directive()
                if not directive_str:
                    return
                    
                # 解析新指令
                try:
                    new_directive = self.parser.parse_string(directive_str)
                    if not new_directive:
                        raise ValueError("指令解析失败")
                except Exception as e:
                    QMessageBox.critical(self, "错误", f"指令解析失败: {str(e)}")
                    return
                
                # 获取块数据
                block = item.data(0, Qt.ItemDataRole.UserRole)
                if not block or not isinstance(block, ParseResults):
                    raise ValueError("无效的配置块")
                
                # 确保块有正确的结构
                if len(block) < 2:
                    block.append(ParseResults([]))
                elif not isinstance(block[-1], ParseResults):
                    block.append(ParseResults([]))
                
                # 添加新指令到块中
                if new_directive and len(new_directive) > 0:
                    block[-1].append(new_directive[0])
                    
                    # 保存当前选中的项的路径
                    current_path = []
                    temp_item = item
                    while temp_item:
                        current_path.insert(0, (temp_item.text(0), temp_item.text(1)))
                        temp_item = temp_item.parent()
                    
                    # 保存配置
                    if self.save_config():
                        # 更新树视图
                        self.update_tree()
                        
                        # 找到并选中之前的项
                        self._select_item_by_path(current_path)
                        
                        QMessageBox.information(self, "成功", "指令已添加并保存")
                    else:
                        QMessageBox.warning(self, "警告", "指令已添加但保存失败")
            
            except Exception as e:
                QMessageBox.critical(self, "错误", f"添加指令失败: {str(e)}")
                import traceback
                print(traceback.format_exc())

    def _select_item_by_path(self, path):
        """根据路径查找并选中树节点"""
        def find_item(current_item, remaining_path):
            if not remaining_path:
                return current_item
            
            target_text, target_value = remaining_path[0]
            for i in range(current_item.childCount()):
                child = current_item.child(i)
                if (child.text(0) == target_text and 
                    child.text(1) == target_value):
                    return find_item(child, remaining_path[1:])
            return None
        
        # 从根节点开始查找
        root = self.tree.invisibleRootItem()
        found_item = find_item(root, path)
        
        if found_item:
            # 选中并展开找到的项
            self.tree.setCurrentItem(found_item)
            found_item.setExpanded(True)
            
            # 确保父节点都被展开
            parent = found_item.parent()
            while parent:
                parent.setExpanded(True)
                parent = parent.parent()

    def edit_block(self, item):
        """编辑块"""
        block_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not block_data:
            return
            
        block_type = str(block_data[0]) if len(block_data) > 0 else ""
        
        if block_type == "server":
            dialog = ServerConfigDialog(self, block_data)
            if dialog.exec():
                try:
                    # 获取新的配置内容
                    new_config = dialog.get_config()
                    
                    # 解析新的配置块
                    new_block = self.parser.parse_block(new_config)
                    
                    # 更新原块
                    for i, val in enumerate(new_block):
                        if i < len(block_data):
                            block_data[i] = val
                        else:
                            block_data.append(val)
                    
                    # 更新树视图
                    self.update_tree()
                    
                    # 保存配置文件
                    self.save_config()
                    
                except Exception as e:
                    QMessageBox.critical(self, "错误", f"编辑块失败: {str(e)}")
        elif block_type == "location":
            dialog = BlockDialog(self, self.parser.get_context_info(block_type))
            if dialog.exec():
                try:
                    block_params = dialog.get_block_content()
                    
                    # 验证上下文
                    if not self.parser.validate_context(block_type, block_type):
                        raise ValueError(f"{block_type} 块不能在 {block_type} 中使用")
                    
                    # 创建新块
                    new_block = self.parser.parse_block(f"{block_type} {block_params} {{\n}}")
                    
                    # 更新原块
                    for i, val in enumerate(new_block):
                        if i < len(block_data):
                            block_data[i] = val
                        else:
                            block_data.append(val)
                    
                    # 更新树视图
                    self.update_tree()
                    
                    # 保存配置文件
                    self.save_config()
                    
                except Exception as e:
                    QMessageBox.critical(self, "错误", f"编辑块失败: {str(e)}")
        else:
            # 其他类型的块
            dialog = BlockDialog(self, self.parser.get_context_info(block_type))
            if dialog.exec():
                try:
                    block_params = dialog.get_block_content()
                    
                    # 验证上下文
                    if not self.parser.validate_context(block_type, block_type):
                        raise ValueError(f"{block_type} 块不能在 {block_type} 中使用")
                    
                    # 创建新块
                    new_block = self.parser.parse_block(f"{block_type} {block_params} {{\n}}")
                    
                    # 更新原块
                    for i, val in enumerate(new_block):
                        if i < len(block_data):
                            block_data[i] = val
                        else:
                            block_data.append(val)
                    
                    # 更新树视图
                    self.update_tree()
                    
                    # 保存配置文件
                    self.save_config()
                    
                except Exception as e:
                    QMessageBox.critical(self, "错误", f"编辑块失败: {str(e)}")

    def delete_block(self, item):
        """删除配置块"""
        reply = QMessageBox.question(
            self,
            "确认删除",
            "确定要删除这个配置块吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                block = item.data(0, Qt.ItemDataRole.UserRole)
                parent = item.parent()
                if parent:
                    parent_block = parent.data(0, Qt.ItemDataRole.UserRole)
                    if isinstance(parent_block[-1], ParseResults):
                        # 找到块在父块中的索引并删除
                        for i, b in enumerate(parent_block[-1]):
                            if b is block:  # 使用 is 进行身份比较
                                del parent_block[-1][i]
                                break
                            
                        # 更新树视图
                        self.update_tree()
                        # 保存配置文件
                        self.save_config()
                        
            except Exception as e:
                QMessageBox.critical(self, "错误", f"删除配置块失败: {str(e)}")

    def save_config(self):
        """保存配置文件"""
        if not self.current_config_path:
            QMessageBox.warning(self, "警告", "没有指定配置文件路径")
            return False
            
        try:
            # 生成配置文件内容
            content = self.parser.to_string()
            
            # 创建备份文件
            backup_path = f"{self.current_config_path}.bak"
            if os.path.exists(self.current_config_path):
                import shutil
                shutil.copy2(self.current_config_path, backup_path)
            
            # 保存新的配置
            with open(self.current_config_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            return True
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存配置失败: {str(e)}")
            # 如果保存失败且存在备份，则恢复备份
            if os.path.exists(backup_path):
                import shutil
                try:
                    shutil.copy2(backup_path, self.current_config_path)
                except Exception as backup_e:
                    QMessageBox.critical(self, "错误", f"恢复备份失败: {str(backup_e)}")
            return False

    def use_template(self):
        """使用配置模板"""
        dialog = TemplateDialog(self)
        if dialog.exec():
            try:
                template_content = dialog.preview.toPlainText().strip()
                
                # 确保配置树已初始化
                if self.parser.config_tree is None:
                    self.parser.config_tree = []
                
                # 解析模板内容
                try:
                    new_block = self.parser.parse_block(template_content)
                    if not new_block:
                        raise ValueError("模板解析结果为空")
                except Exception as e:
                    QMessageBox.critical(self, "解析错误", str(e))
                    return
                
                # 查找或创建http块
                http_block = None
                for item in self.parser.config_tree:
                    if isinstance(item, ParseResults) and len(item) > 0 and item[0] == 'http':
                        http_block = item
                        break
                
                # 如果没有找到http块，创建一个新的
                if not http_block:
                    try:
                        http_block = self.parser.parse_block("http {}")
                        self.parser.config_tree.append(http_block)
                    except Exception as e:
                        QMessageBox.critical(self, "错误", f"创建http块失败: {str(e)}")
                        return
                
                # 确保http块有正确的结构
                if len(http_block) < 2 or not isinstance(http_block[-1], ParseResults):
                    http_block.append(ParseResults([]))
                
                # 添加新的server块
                if new_block[0] in ['server', 'upstream']:
                    http_block[-1].append(new_block)
                else:
                    self.parser.config_tree.append(new_block)
                
                # 更新树视图
                self.update_tree()
                
                # 保存配置文件
                if self.save_config():
                    QMessageBox.information(self, "成功", "配置模板已应用")
                
            except Exception as e:
                QMessageBox.critical(self, "错误", f"应用模板失败: {str(e)}")
                import traceback
                print(traceback.format_exc())
                
    def validate_config(self):
        """验证配置"""
        if not self.current_config_path:
            QMessageBox.warning(self, "警告", "没有指定配置文件路径")
            return
            
        try:
            # 保存当前配置到临时文件
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
                temp.write(self.parser.to_string())
                temp_path = temp.name
            
            # 使用nginx -t验证配置
            import subprocess
            result = subprocess.run(
                ['nginx', '-t', '-c', temp_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                QMessageBox.information(self, "成功", "配置验证通过")
            else:
                QMessageBox.warning(self, "警告", f"配置验证失败:\n{result.stderr}")
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"验证配置失败: {str(e)}")
            
        finally:
            # 清理临时文件
            if 'temp_path' in locals():
                try:
                    os.remove(temp_path)
                except:
                    pass
                    
    def export_config(self):
        """导出配置"""
        if not self.current_config_path:
            QMessageBox.warning(self, "警告", "没有指定配置文件路径")
            return
            
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = f"{os.path.splitext(self.current_config_path)[0]}_{timestamp}.conf"
            
            with open(export_path, 'w', encoding='utf-8') as f:
                f.write(self.parser.to_string())
                
            QMessageBox.information(self, "成功", f"配置已导出到:\n{export_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出配置失败: {str(e)}") 