# secure_db.py
# 这个模块负责处理加密数据库的连接和操作
# 使用文件级加密保护整个数据库文件

import sqlite3
import os
import json
import tempfile
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class SecureDatabase:
    """
    安全数据库类，提供对加密SQLite数据库的访问
    使用Fernet对整个数据库文件进行加密，确保数据安全
    """
    def __init__(self, db_path: str, password: str):
        """
        初始化安全数据库连接
        
        参数:
            db_path: 数据库文件路径
            password: 数据库主密码
        """
        self.db_path = db_path
        self.password = password
        self.conn = None
        self.temp_db_path = None
        
        # 从主密码生成加密密钥
        self.fernet = self._create_fernet_from_password(password)
        
        # 创建验证文件路径（用于验证主密码）
        self.auth_file = f"{os.path.splitext(db_path)[0]}.auth"

    def _create_fernet_from_password(self, password):
        """
        从用户密码创建Fernet加密对象
        
        参数:
            password: 用户密码
            
        返回:
            Fernet对象，用于加密和解密数据
        """
        # 使用固定的盐值（在实际应用中，应该为每个用户生成并存储唯一的盐值）
        salt = b'password_manager_salt'
        
        # 从密码派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def connect(self):
        """
        连接数据库并验证密码
        如果密码错误，将抛出异常
        """
        # 验证密码是否正确
        if os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, 'rb') as f:
                    encrypted_data = f.read()
                
                # 尝试解密验证数据
                try:
                    self.fernet.decrypt(encrypted_data)
                    print("主密码验证成功")
                except Exception:
                    raise ValueError("数据库密码错误")
            except Exception as e:
                raise ValueError(f"验证密码时出错: {str(e)}")
        
        # 创建临时文件
        fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        print(f"创建临时数据库文件: {self.temp_db_path}")
        
        # 如果加密数据库文件存在，则解密到临时文件
        if os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0:
            try:
                print(f"开始解密数据库文件: {self.db_path}")
                # 解密数据库文件
                with open(self.db_path, 'rb') as f:
                    encrypted_data = f.read()
                
                print(f"读取到加密数据: {len(encrypted_data)} 字节")
                    
                if encrypted_data:  # 确保有数据要解密
                    try:
                        decrypted_data = self.fernet.decrypt(encrypted_data)
                        print(f"解密成功，解密后数据大小: {len(decrypted_data)} 字节")
                        
                        with open(self.temp_db_path, 'wb') as f:
                            f.write(decrypted_data)
                        print(f"解密数据已写入临时文件: {self.temp_db_path}")
                    except Exception as e:
                        print(f"解密数据库文件失败: {str(e)}")
                        # 如果解密失败，可能是新文件或密码错误
                        # 如果是验证通过但解密失败，可能是文件损坏
                        if os.path.exists(self.auth_file):
                            # 如果验证通过但解密失败，创建一个新的空数据库
                            print("创建新的空数据库")
                            # 创建一个新的空数据库文件
                            # 删除原数据库文件，防止文件损坏影响下次读取
                            try:
                                os.remove(self.db_path)
                                print(f"已删除损坏的数据库文件: {self.db_path}")
                            except Exception as e:
                                print(f"删除损坏数据库文件失败: {str(e)}")
                            
                            # 创建一个新的空数据库文件
                            # 不需要额外操作，因为我们已经创建了临时数据库文件，
                            # 在程序结束时会自动加密并保存
            except Exception as e:
                print(f"处理数据库文件时出错: {str(e)}")
        else:
            print(f"数据库文件不存在或为空，将创建新数据库: {self.db_path}")
        
        # 连接到解密后的数据库或新数据库
        self.conn = sqlite3.connect(self.temp_db_path)
        print(f"已连接到数据库: {self.temp_db_path}")
        
        # 启用外键约束
        self.conn.execute("PRAGMA foreign_keys = ON")

    def initialize(self):
        """
        初始化密码表结构
        如果表不存在则创建，并创建验证文件
        """
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                name TEXT,
                url TEXT,
                username TEXT,
                password TEXT
            )
        """)
        self.conn.commit()
        
        # 创建验证文件（如果不存在）
        if not os.path.exists(self.auth_file):
            # 加密一个简单的验证数据
            test_data = self.fernet.encrypt(b"password_verification")
            with open(self.auth_file, 'wb') as f:
                f.write(test_data)

    def execute(self, sql: str, params=()):
        """
        执行SQL语句并提交更改
        
        参数:
            sql: SQL语句
            params: SQL参数元组
            
        返回:
            游标对象
        """
        try:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            self.conn.commit()
            
            # 只在修改数据时保存加密数据库
            if sql.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                print(f"执行了修改操作: {sql[:30]}...")
                self._save_encrypted_db()
            
            return cur
        except Exception as e:
            print(f"执行SQL时出错: {str(e)}, SQL: {sql}")
            raise

    def fetchall(self, sql: str, params=()):
        """
        执行查询并返回所有结果
        
        参数:
            sql: SQL查询语句
            params: SQL参数元组
            
        返回:
            查询结果列表
        """
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
        
    def _save_encrypted_db(self):
        """
        将当前数据库状态加密并保存到磁盘
        """
        try:
            if self.conn and self.temp_db_path:
                # 确保所有更改已提交
                self.conn.commit()
                
                # 将数据库文件读入内存
                with open(self.temp_db_path, 'rb') as f:
                    db_data = f.read()
                
                if db_data:  # 确保有数据要加密
                    # 加密数据库文件
                    encrypted_data = self.fernet.encrypt(db_data)
                    
                    # 写入加密数据到磁盘
                    with open(self.db_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # 打印调试信息
                    print(f"数据库已加密并保存到: {self.db_path} (大小: {len(encrypted_data)} 字节)")
        except Exception as e:
            print(f"保存加密数据库时出错: {str(e)}")

    def close(self):
        """
        关闭数据库连接并清理临时文件
        """
        if self.conn:
            try:
                # 确保最后一次保存
                print("关闭数据库前保存加密数据...")
                self._save_encrypted_db()
                self.conn.close()
                print("数据库连接已关闭")
                
                # 删除临时数据库文件
                if self.temp_db_path and os.path.exists(self.temp_db_path):
                    try:
                        os.remove(self.temp_db_path)
                        print(f"临时数据库文件已删除: {self.temp_db_path}")
                    except Exception as e:
                        print(f"删除临时数据库文件失败: {str(e)}")
            except Exception as e:
                print(f"关闭数据库时出错: {str(e)}")


if __name__ == "__main__":
    # 简单的使用示例
    db = SecureDatabase("secure.db", "MyMasterPassword")
    db.connect()
    db.initialize()

    # 插入测试数据
    db.execute("INSERT INTO passwords (name, url, username, password) VALUES (?, ?, ?, ?)", 
               ("Google", "https://google.com", "user@gmail.com", "myStrongPass"))

    # 读取并显示所有记录
    for row in db.fetchall("SELECT * FROM passwords"):
        print(row)

    db.close()
