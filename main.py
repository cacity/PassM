# main.py
# 密码管理器主程序
# 提供图形界面，实现密码的管理、添加、删除和导入功能
# 使用 sqlite3 和 cryptography 库实现密码加密
# 运行前需要安装依赖：pip install PyQt5 cryptography

import sys
import os
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QTableWidget, QTableWidgetItem, QHeaderView, 
                            QMessageBox, QFileDialog, QDialog, QFormLayout,
                            QAction, QMenu, QToolBar, QStatusBar,  QComboBox,QSlider,QGroupBox,QCheckBox)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont, QClipboard

from secure_db import SecureDatabase
from importer import import_chrome_csv

# 全局样式
STYLE = """
QWidget {
    font-family: 'Segoe UI', Arial;
    font-size: 10pt;
}
QPushButton {
    background-color: #0078d7;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #005a9e;
}
QPushButton:pressed {
    background-color: #004275;
}
QLineEdit {
    padding: 8px;
    border: 1px solid #ccc;
    border-radius: 4px;
}
QTableWidget {
    border: 1px solid #ddd;
    gridline-color: #f0f0f0;
}
QHeaderView::section {
    background-color: #f5f5f5;
    padding: 6px;
    border: 1px solid #ddd;
    font-weight: bold;
}
"""

class LoginDialog(QDialog):
    """登录对话框，用于输入主密码"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("密码管理器 - 登录")
        self.setMinimumWidth(350)
        self.setWindowIcon(QIcon('./icons/icons8-password-96.png'))
        self.setup_ui()
        
    def setup_ui(self):
        """设置登录界面UI"""
        layout = QVBoxLayout()
        
        # 标题
        title_label = QLabel("请输入主密码")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # 说明
        info_label = QLabel("输入主密码解锁您的密码库")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # 密码输入框
        form_layout = QFormLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("输入主密码")
        form_layout.addRow("主密码:", self.password_edit)
        layout.addLayout(form_layout)
        
        # 数据库路径
        self.db_path_edit = QLineEdit("secure.db")
        self.db_path_edit.setPlaceholderText("数据库文件路径")
        form_layout.addRow("数据库:", self.db_path_edit)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("登录")
        self.login_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("取消")
        self.cancel_button.clicked.connect(self.reject)
        
        # 设置取消按钮样式为灰色
        self.cancel_button.setStyleSheet("background-color: #888;")
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.login_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def get_credentials(self):
        """获取用户输入的凭据"""
        return self.db_path_edit.text(), self.password_edit.text()


class PasswordGeneratorDialog(QDialog):
    """密码生成器对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("生成密码")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon('./icons/icons8-password-96.png'))
        self.generated_password = ""
        self.setup_ui()
        
    def setup_ui(self):
        """设置密码生成器界面"""
        layout = QVBoxLayout()
        
        # 密码长度
        length_layout = QHBoxLayout()
        length_label = QLabel("密码长度:")
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(32)
        self.length_slider.setValue(16)
        self.length_slider.setTickPosition(QSlider.TicksBelow)
        self.length_slider.setTickInterval(4)
        self.length_slider.valueChanged.connect(self.update_length_label)
        
        self.length_value = QLabel("16")
        
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_slider)
        length_layout.addWidget(self.length_value)
        layout.addLayout(length_layout)
        
        # 密码类型选项
        options_group = QGroupBox("包含字符类型")
        options_layout = QVBoxLayout()
        
        self.uppercase_check = QCheckBox("大写字母 (A-Z)")
        self.uppercase_check.setChecked(True)
        options_layout.addWidget(self.uppercase_check)
        
        self.lowercase_check = QCheckBox("小写字母 (a-z)")
        self.lowercase_check.setChecked(True)
        options_layout.addWidget(self.lowercase_check)
        
        self.numbers_check = QCheckBox("数字 (0-9)")
        self.numbers_check.setChecked(True)
        options_layout.addWidget(self.numbers_check)
        
        self.special_check = QCheckBox("特殊字符 (!@#$%^&*...)")
        self.special_check.setChecked(True)
        options_layout.addWidget(self.special_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # 自定义特殊字符
        custom_layout = QHBoxLayout()
        custom_label = QLabel("自定义特殊字符:")
        self.custom_chars = QLineEdit("!@#$%^&*()_+-=[]{}|;:,.<>/?")
        custom_layout.addWidget(custom_label)
        custom_layout.addWidget(self.custom_chars)
        layout.addLayout(custom_layout)
        
        # 生成的密码显示
        password_layout = QHBoxLayout()
        password_label = QLabel("生成的密码:")
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setEchoMode(QLineEdit.Password)
        
        self.toggle_view_btn = QPushButton("显示")
        self.toggle_view_btn.setCheckable(True)
        self.toggle_view_btn.toggled.connect(self.toggle_password_view)
        
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_display)
        password_layout.addWidget(self.toggle_view_btn)
        layout.addLayout(password_layout)
        
        # 按钮
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("生成密码")
        self.generate_button.clicked.connect(self.generate_password)
        
        self.cancel_button = QPushButton("取消")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet("background-color: #888;")
        
        self.use_button = QPushButton("使用此密码")
        self.use_button.clicked.connect(self.accept)
        self.use_button.setEnabled(False)
        
        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.use_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # 初始化生成一个密码
        self.generate_password()
    
    def update_length_label(self, value):
        """更新密码长度标签"""
        self.length_value.setText(str(value))
    
    def toggle_password_view(self, checked):
        """切换密码显示/隐藏"""
        if checked:
            self.password_display.setEchoMode(QLineEdit.Normal)
            self.toggle_view_btn.setText("隐藏")
        else:
            self.password_display.setEchoMode(QLineEdit.Password)
            self.toggle_view_btn.setText("显示")
    
    def generate_password(self):
        """生成随机密码"""
        import random
        import string
        
        # 获取用户选项
        length = self.length_slider.value()
        chars = []
        
        if self.uppercase_check.isChecked():
            chars.extend(list(string.ascii_uppercase))
        
        if self.lowercase_check.isChecked():
            chars.extend(list(string.ascii_lowercase))
        
        if self.numbers_check.isChecked():
            chars.extend(list(string.digits))
        
        if self.special_check.isChecked():
            chars.extend(list(self.custom_chars.text()))
        
        if not chars:
            # 如果没有选择任何字符类型，默认使用小写字母
            chars = list(string.ascii_lowercase)
            self.lowercase_check.setChecked(True)
        
        # 生成密码
        password = ''.join(random.choice(chars) for _ in range(length))
        self.password_display.setText(password)
        self.generated_password = password
        self.use_button.setEnabled(True)


class AddPasswordDialog(QDialog):
    """添加新密码对话框"""
    
    def __init__(self, parent=None, db=None):
        super().__init__(parent)
        self.setWindowTitle("添加新密码")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon('./icons/icons8-password-96.png'))
        self.db = db  # 保存数据库引用以获取历史用户名
        self.setup_ui()
        self.load_username_history()  # 加载历史用户名
        
    def setup_ui(self):
        """设置添加密码界面UI"""
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如: 抖音, 头条等")
        form_layout.addRow("网站名称:", self.name_edit)
        
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("例如: https://www.douyin.com")
        form_layout.addRow("网址:", self.url_edit)
        
        # 使用下拉列表代替线性编辑框，支持历史记录
        self.username_combo = QComboBox()
        self.username_combo.setEditable(True)  # 允许用户编辑
        self.username_combo.setInsertPolicy(QComboBox.NoInsert)  # 防止自动添加到列表
        self.username_combo.setPlaceholderText("您的登录用户名或邮箱")
        form_layout.addRow("用户名:", self.username_combo)
        
        # 密码输入区域
        password_layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("您的密码")
        
        self.show_password_btn = QPushButton("显示")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setMaximumWidth(60)
        self.show_password_btn.toggled.connect(self.toggle_password_view)
        
        self.generate_password_btn = QPushButton("生成")
        self.generate_password_btn.setMaximumWidth(60)
        self.generate_password_btn.clicked.connect(self.open_password_generator)
        
        password_layout.addWidget(self.password_edit)
        password_layout.addWidget(self.show_password_btn)
        password_layout.addWidget(self.generate_password_btn)
        
        form_layout.addRow("密码:", password_layout)
        layout.addLayout(form_layout)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.cancel_button = QPushButton("取消")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet("background-color: #888;")
        
        self.save_button = QPushButton("保存")
        self.save_button.clicked.connect(self.accept)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.save_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_username_history(self):
        """从数据库加载历史用户名"""
        if self.db:
            try:
                # 查询不同的用户名
                results = self.db.fetchall("SELECT DISTINCT username FROM passwords WHERE username IS NOT NULL AND username != ''")
                usernames = [row[0] for row in results]
                
                # 添加到下拉列表
                self.username_combo.addItems(usernames)
            except Exception as e:
                print(f"加载用户名历史记录时出错: {str(e)}")
    
    def toggle_password_view(self, checked):
        """切换密码显示/隐藏"""
        if checked:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("隐藏")
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("显示")
    
    def open_password_generator(self):
        """打开密码生成器对话框"""
        generator_dialog = PasswordGeneratorDialog(self)
        if generator_dialog.exec_():
            # 如果用户点击了“使用此密码”按钮
            self.password_edit.setText(generator_dialog.generated_password)
    
    def get_password_data(self):
        """获取用户输入的密码数据"""
        return {
            "name": self.name_edit.text(),
            "url": self.url_edit.text(),
            "username": self.username_combo.currentText(),
            "password": self.password_edit.text()
        }


class PasswordManager(QMainWindow):
    """密码管理器主窗口"""
    
    def __init__(self):
        super().__init__()
        self.db = None
        self.setWindowTitle("密码管理器")
        self.setMinimumSize(800, 600)
        self.setWindowIcon(QIcon('./icons/icons8-password-96.png'))
        self.setup_ui()
        
        # 显示登录对话框
        self.show_login_dialog()
        
    def setup_ui(self):
        """设置主界面UI"""
        # 设置中央窗口
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 创建工具栏
        self.create_toolbar()
        
        # 搜索框
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索:")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("输入关键词搜索...")
        self.search_edit.textChanged.connect(self.filter_passwords)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        main_layout.addLayout(search_layout)
        
        # 密码表格
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(5)
        self.password_table.setHorizontalHeaderLabels(["ID", "网站名称", "网址", "用户名", "密码"])
        self.password_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.password_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.password_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.password_table.cellDoubleClicked.connect(self.copy_to_clipboard)
        main_layout.addWidget(self.password_table)
        
        # 状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("准备就绪")
        
    def create_toolbar(self):
        """创建工具栏"""
        toolbar = QToolBar("主工具栏")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)
        
        # 添加密码按钮
        add_action = QAction("添加密码", self)
        add_action.triggered.connect(self.add_password)
        toolbar.addAction(add_action)
        
        # 删除密码按钮
        delete_action = QAction("删除密码", self)
        delete_action.triggered.connect(self.delete_password)
        toolbar.addAction(delete_action)
        
        toolbar.addSeparator()
        
        # 导入密码按钮
        import_action = QAction("导入Chrome密码", self)
        import_action.triggered.connect(self.import_passwords)
        toolbar.addAction(import_action)
        
        toolbar.addSeparator()
        
        # 刷新按钮
        refresh_action = QAction("刷新", self)
        refresh_action.triggered.connect(self.load_passwords)
        toolbar.addAction(refresh_action)
        
    def show_login_dialog(self):
        """显示登录对话框"""
        login_dialog = LoginDialog(self)
        if login_dialog.exec_():
            db_path, password = login_dialog.get_credentials()
            try:
                self.db = SecureDatabase(db_path, password)
                self.db.connect()
                self.db.initialize()
                self.load_passwords()
                self.statusBar.showMessage(f"已连接到数据库: {db_path}")
            except ValueError as e:
                QMessageBox.critical(self, "登录失败", str(e))
                self.close()
            except Exception as e:
                QMessageBox.critical(self, "错误", f"连接数据库时出错: {str(e)}")
                self.close()
        else:
            # 用户取消登录
            self.close()
            
    def load_passwords(self):
        """从数据库加载密码"""
        if not self.db:
            return
            
        try:
            passwords = self.db.fetchall("SELECT id, name, url, username, password FROM passwords")
            self.password_table.setRowCount(0)  # 清空表格
            
            for row_idx, password in enumerate(passwords):
                self.password_table.insertRow(row_idx)
                for col_idx, value in enumerate(password):
                    # 如果是密码列，显示为 ******
                    if col_idx == 4:  # 密码列
                        self.password_table.setItem(row_idx, col_idx, QTableWidgetItem("******"))
                    else:
                        self.password_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))
            
            self.statusBar.showMessage(f"已加载 {len(passwords)} 条密码记录")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载密码时出错: {str(e)}")
            
    def filter_passwords(self):
        """根据搜索框内容过滤密码"""
        search_text = self.search_edit.text().lower()
        
        for row in range(self.password_table.rowCount()):
            match = False
            for col in range(1, 4):  # 只搜索名称、网址和用户名列
                item = self.password_table.item(row, col)
                if item and search_text in item.text().lower():
                    match = True
                    break
            
            self.password_table.setRowHidden(row, not match)
            
    def add_password(self):
        """添加新密码"""
        dialog = AddPasswordDialog(self, self.db)  # 传递数据库对象
        if dialog.exec_():
            password_data = dialog.get_password_data()
            
            try:
                self.db.execute(
                    "INSERT INTO passwords (name, url, username, password) VALUES (?, ?, ?, ?)",
                    (password_data["name"], password_data["url"], 
                     password_data["username"], password_data["password"])
                )
                self.load_passwords()
                self.statusBar.showMessage("密码添加成功")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"添加密码时出错: {str(e)}")
                
    def delete_password(self):
        """删除选中的密码"""
        selected_rows = self.password_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "提示", "请先选择要删除的密码")
            return
            
        confirm = QMessageBox.question(
            self, "确认删除", 
            f"确定要删除选中的 {len(selected_rows)} 条密码记录吗？",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            try:
                for row in sorted(selected_rows, reverse=True):
                    password_id = self.password_table.item(row.row(), 0).text()
                    self.db.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
                
                self.load_passwords()
                self.statusBar.showMessage(f"已删除 {len(selected_rows)} 条密码记录")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"删除密码时出错: {str(e)}")
                
    def import_passwords(self):
        """导入Chrome密码"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择Chrome密码CSV文件", "", "CSV文件 (*.csv)"
        )
        
        if not file_path:
            return
            
        try:
            count = import_chrome_csv(file_path, self.db)
            self.load_passwords()
            QMessageBox.information(self, "导入成功", f"成功导入 {count} 条密码记录")
        except Exception as e:
            QMessageBox.critical(self, "导入失败", str(e))
            
    def copy_to_clipboard(self, row, column):
        """双击表格单元格时复制内容到剪贴板"""
        if column == 4:  # 密码列
            # 获取真实密码
            password_id = self.password_table.item(row, 0).text()
            try:
                result = self.db.fetchall("SELECT password FROM passwords WHERE id = ?", (password_id,))
                if result:
                    password = result[0][0]
                    clipboard = QApplication.clipboard()
                    clipboard.setText(password)
                    self.statusBar.showMessage("密码已复制到剪贴板，10秒后将清除", 10000)
                    # 10秒后清除剪贴板
                    QApplication.processEvents()
                    import threading
                    threading.Timer(10.0, lambda: clipboard.setText("")).start()
            except Exception as e:
                QMessageBox.critical(self, "错误", f"复制密码时出错: {str(e)}")
        else:
            # 复制其他列的内容
            item = self.password_table.item(row, column)
            if item:
                QApplication.clipboard().setText(item.text())
                self.statusBar.showMessage("内容已复制到剪贴板")
                
    def closeEvent(self, event):
        """窗口关闭时关闭数据库连接"""
        if self.db:
            self.db.close()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())
