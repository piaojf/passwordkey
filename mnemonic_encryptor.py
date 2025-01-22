import tkinter as tk
from tkinter import messagebox
import secrets
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
import string
import random
import cryptography.exceptions

class MnemonicEncryptor:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("助记词加密工具")
        self.window.geometry("700x600")  # 增加窗口大小
        self.window.configure(bg='#f0f0f0')  # 设置背景色
        
        # 设置统一的样式
        self.style = {
            'bg': '#f0f0f0',
            'button_bg': '#2196F3',
            'button_fg': 'white',
            'entry_bg': 'white',
            'label_fg': '#333333',
            'font': ('Microsoft YaHei UI', 10),
            'button_font': ('Microsoft YaHei UI', 10, 'bold'),
            'title_font': ('Microsoft YaHei UI', 12, 'bold'),
            'padding': 10
        }
        
        # 主容器
        main_frame = tk.Frame(self.window, bg=self.style['bg'])
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # 加密部分标题
        tk.Label(main_frame, text="加密助记词", font=self.style['title_font'], 
                bg=self.style['bg'], fg=self.style['label_fg']).pack(pady=(0,10))
        
        # 助记词输入区
        tk.Label(main_frame, text="请输入12位助记词:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(pady=(5,0))
        self.mnemonic_entry = tk.Entry(main_frame, width=50, font=self.style['font'],
                                      bg=self.style['entry_bg'])
        self.mnemonic_entry.pack(pady=5)
        
        # 密码输入区域
        password_frame = tk.Frame(main_frame, bg=self.style['bg'])
        password_frame.pack(pady=10)
        
        # 第一个密码输入框
        password_input_frame = tk.Frame(password_frame, bg=self.style['bg'])
        password_input_frame.pack(fill=tk.X, pady=2)
        tk.Label(password_input_frame, text="请输入二次密码:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(side=tk.LEFT)
        self.password_entry = tk.Entry(password_input_frame, width=30, show="*",
                                     font=self.style['font'], bg=self.style['entry_bg'])
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # 美化按钮
        self.show_password1 = tk.Button(password_input_frame, text="👁", 
                                      command=lambda: self.toggle_password(self.password_entry),
                                      relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                      font=self.style['font'])
        self.show_password1.pack(side=tk.LEFT, padx=2)
        
        self.generate_button = tk.Button(password_input_frame, text="随机生成",
                                       command=self.generate_and_fill_password,
                                       relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                       font=self.style['font'])
        self.generate_button.pack(side=tk.LEFT, padx=5)
        
        # 第二个密码输入框（类似样式）
        password_confirm_frame = tk.Frame(password_frame, bg=self.style['bg'])
        password_confirm_frame.pack(fill=tk.X, pady=2)
        tk.Label(password_confirm_frame, text="请确认二次密码:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(side=tk.LEFT)
        self.password_confirm = tk.Entry(password_confirm_frame, width=30, show="*",
                                       font=self.style['font'], bg=self.style['entry_bg'])
        self.password_confirm.pack(side=tk.LEFT, padx=5)
        self.show_password2 = tk.Button(password_confirm_frame, text="👁",
                                      command=lambda: self.toggle_password(self.password_confirm),
                                      relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                      font=self.style['font'])
        self.show_password2.pack(side=tk.LEFT, padx=2)
        
        # 加密按钮
        self.encrypt_button = tk.Button(main_frame, text="生成二次密钥", command=self.encrypt,
                                      relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                      font=self.style['button_font'], width=15)
        self.encrypt_button.pack(pady=10)
        
        # 加密结果区域
        result_frame = tk.Frame(main_frame, bg=self.style['bg'])
        result_frame.pack(pady=5)
        
        tk.Label(result_frame, text="加密后的二次密钥:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(side=tk.LEFT, pady=(5,0))
        
        # 添加复制按钮到密钥文本框旁边
        copy_button = tk.Button(result_frame, text="复制",
                              command=self.copy_encrypted_key,
                              relief=tk.FLAT, bg=self.style['button_bg'],
                              fg=self.style['button_fg'],
                              font=self.style['font'])
        copy_button.pack(side=tk.LEFT, padx=5, pady=(5,0))
        
        self.encrypted_text = tk.Text(main_frame, height=4, width=50, font=self.style['font'],
                                    bg=self.style['entry_bg'])
        self.encrypted_text.pack(pady=5)
        
        # 分割线
        separator = tk.Frame(main_frame, height=2, bg='#cccccc')
        separator.pack(fill=tk.X, pady=15)
        
        # 解密部分标题
        tk.Label(main_frame, text="还原助记词", font=self.style['title_font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(pady=(5,10))
        
        # 解密输入区域
        tk.Label(main_frame, text="请输入二次密钥:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(pady=(5,0))
        self.decrypt_key_entry = tk.Text(main_frame, height=4, width=50, font=self.style['font'],
                                       bg=self.style['entry_bg'])
        self.decrypt_key_entry.pack(pady=5)
        
        # 解密密码输入框
        decrypt_password_frame = tk.Frame(main_frame, bg=self.style['bg'])
        decrypt_password_frame.pack(pady=5)
        tk.Label(decrypt_password_frame, text="请输入二次密码:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(side=tk.LEFT)
        self.decrypt_password_entry = tk.Entry(decrypt_password_frame, width=30, show="*",
                                             font=self.style['font'], bg=self.style['entry_bg'])
        self.decrypt_password_entry.pack(side=tk.LEFT, padx=5)
        self.show_decrypt_password = tk.Button(decrypt_password_frame, text="👁",
                                             command=lambda: self.toggle_password(self.decrypt_password_entry),
                                             relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                             font=self.style['font'])
        self.show_decrypt_password.pack(side=tk.LEFT)
        
        # 解密按钮
        self.decrypt_button = tk.Button(main_frame, text="还原助记词", command=self.decrypt,
                                      relief=tk.FLAT, bg=self.style['button_bg'], fg=self.style['button_fg'],
                                      font=self.style['button_font'], width=15)
        self.decrypt_button.pack(pady=10)
        
        # 解密结果
        tk.Label(main_frame, text="还原后的助记词:", font=self.style['font'],
                bg=self.style['bg'], fg=self.style['label_fg']).pack(pady=(5,0))
        self.decrypted_text = tk.Entry(main_frame, width=50, font=self.style['font'],
                                      bg=self.style['entry_bg'])
        self.decrypted_text.pack(pady=5)

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # 建议增加密码长度检查
        if len(password) < 8:  # 添加最小密码长度要求
            raise ValueError("密码长度必须至少为8位")
        
        # 简化密钥派生过程，直接使用 PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,  # 增加迭代次数
        )
        key = kdf.derive(password.encode())
        return key, salt

    def toggle_password(self, entry_widget):
        """切换密码显示/隐藏"""
        if entry_widget.cget('show') == '*':
            entry_widget.configure(show='')
        else:
            entry_widget.configure(show='*')

    def encrypt(self):
        try:
            mnemonic = self.mnemonic_entry.get().strip()
            # 添加助记词格式验证
            words = mnemonic.split()
            if not all(word.isalpha() for word in words):  # 确保所有词都是字母
                messagebox.showerror("错误", "助记词格式不正确")
                return
            password = self.password_entry.get().strip()
            password_confirm = self.password_confirm.get().strip()
            
            if not mnemonic or not password or not password_confirm:
                messagebox.showerror("错误", "助记词和密码不能为空")
                return
            
            if password != password_confirm:
                messagebox.showerror("错误", "两次输入的密码不一致")
                return
            
            if len(mnemonic.split()) != 12:
                messagebox.showerror("错误", "请输入12个助记词")
                return
                
            # 生成加密密钥
            key, salt = self.derive_key(password)
            
            # 使用AES-GCM进行加密
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, mnemonic.encode('utf-8'), None)
            
            # 组合加密数据
            encrypted_data = base64.b64encode(salt + nonce + ciphertext).decode('utf-8')
            self.encrypted_text.delete(1.0, tk.END)
            self.encrypted_text.insert(1.0, encrypted_data)
            
            messagebox.showinfo("成功", "加密成功！请保存好二次密钥。")
            
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def decrypt(self):
        try:
            encrypted_data = self.decrypt_key_entry.get(1.0, tk.END).strip()
            password = self.decrypt_password_entry.get().strip()
            
            if not encrypted_data or not password:
                messagebox.showerror("错误", "密钥和密码不能为空")
                return
            
            try:
                # 解析加密数据
                encrypted_bytes = base64.b64decode(encrypted_data)
                if len(encrypted_bytes) < 29:  # 最小长度检查
                    raise ValueError("无效的加密数据")
                    
                salt = encrypted_bytes[:16]
                nonce = encrypted_bytes[16:28]
                ciphertext = encrypted_bytes[28:]
                
                # 重新生成密钥
                key, _ = self.derive_key(password, salt)
                
                # 解密
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                
                # 验证解密结果
                decrypted_text = decrypted.decode('utf-8')
                if len(decrypted_text.split()) != 12:
                    raise ValueError("解密结果不是有效的12位助记词")
                
                self.decrypted_text.delete(0, tk.END)
                self.decrypted_text.insert(0, decrypted_text)
                
                messagebox.showinfo("成功", "解密成功！")
                
            except ValueError as ve:
                messagebox.showerror("错误", "无效的密钥或密码")
            except Exception as e:
                # 更详细的错误信息
                if isinstance(e, cryptography.exceptions.InvalidTag):
                    messagebox.showerror("错误", "密码错误或数据已损坏")
                else:
                    messagebox.showerror("错误", "解密失败，请检查输入")
            
        except Exception as e:
            messagebox.showerror("错误", "解密过程发生错误")

    def generate_super_strong_password(self):
        """生成超强密码，避免容易混淆的字符"""
        # 基础字符集，排除容易混淆的字符
        lower = "abcdefghijkmnpqrstuvwxyz"  # 排除 l, o
        upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # 排除 I, O
        digits = "23456789"  # 排除 0, 1
        symbols = "@#$%&*+-=[]{}|;:,.<>?"   # 使用清晰的特殊字符
        
        # 确保每种类型都至少使用一次
        password = [
            secrets.choice(upper),
            secrets.choice(lower),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # 填充剩余长度
        all_chars = lower + upper + digits + symbols
        password.extend(secrets.choice(all_chars) for _ in range(18))
        
        # 打乱顺序
        random.shuffle(password)
        return ''.join(password)

    def generate_and_fill_password(self):
        """生成随机密码并填充到密码输入框"""
        password = self.generate_super_strong_password()
        # 清空并填充两个密码输入框
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.password_confirm.delete(0, tk.END)
        self.password_confirm.insert(0, password)
        # 显示提示
        messagebox.showinfo("提示", "已生成随机密码，请务必保存！\n该密码强度很高，请妥善保管。")

    def copy_encrypted_key(self):
        """复制加密后的密钥到剪贴板"""
        encrypted_text = self.encrypted_text.get(1.0, tk.END).strip()
        if encrypted_text:
            self.window.clipboard_clear()
            self.window.clipboard_append(encrypted_text)
            self.window.update()  # 强制更新剪贴板
            messagebox.showinfo("提示", "密钥已复制到剪贴板")
        else:
            messagebox.showwarning("提示", "没有可复制的密钥")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = MnemonicEncryptor()
    app.run() 