import PyInstaller.__main__
import os

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    'mnemonic_encryptor.py',  # 主程序文件
    '--name=助记词加密工具',  # 生成的exe文件名
    '--windowed',  # 使用 GUI 模式
    '--onefile',  # 打包成单个文件
    '--clean',  # 清理临时文件
    '--uac-admin',  # 添加管理员权限请求
    # '--icon=icon.ico',  # 如果有图标文件，取消这行注释
    '--add-data', f'{os.path.join(current_dir, "Microsoft YaHei UI.ttf")};.',  # 添加字体文件
    '--hidden-import=tkinter',
    '--hidden-import=cryptography',
    '--hidden-import=argon2-cffi',
    '--hidden-import=base64',
    '--hidden-import=secrets',
    '--noconfirm',  # 不询问确认
]) 