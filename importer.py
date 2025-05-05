# importer.py
# 这个模块负责导入Chrome浏览器导出的密码CSV文件
# 将CSV文件中的密码数据导入到加密数据库中

import csv
import os
from secure_db import SecureDatabase

def import_chrome_csv(file_path, db):
    """
    从Chrome导出的CSV文件导入密码
    
    参数:
        file_path: CSV文件路径
        db: SecureDatabase实例
    
    CSV格式示例:
    name,url,username,password
    Google,https://google.com,user@gmail.com,myStrongPass
    """
    try:
        with open(file_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                # 插入每一行数据到数据库
                db.execute("INSERT INTO passwords (name, url, username, password) VALUES (?, ?, ?, ?)", (
                    row.get("name", ""),
                    row.get("url", ""),
                    row.get("username", ""),
                    row.get("password", "")
                ))
                count += 1
        return count  # 返回导入的记录数量
    except Exception as e:
        raise Exception(f"导入CSV文件失败: {str(e)}")


if __name__ == "__main__":
    # 测试导入功能
    db = SecureDatabase("secure.db", "MyMasterPassword")
    db.connect()
    db.initialize()
    
    # 假设有一个test_passwords.csv文件
    try:
        count = import_chrome_csv("test_passwords.csv", db)
        print(f"成功导入 {count} 条密码记录")
    except Exception as e:
        print(f"导入失败: {e}")
    finally:
        db.close()
