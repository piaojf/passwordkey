import tkinter as tk
import math
import random
from datetime import time

class ClockApp:
    def __init__(self, root):
        self.root = root
        self.root.title("时钟生成器")
        
        # 创建画布
        self.canvas = tk.Canvas(root, width=400, height=400, bg='#F0F0F0')
        self.canvas.pack(pady=20)
        
        # 创建按钮
        self.generate_btn = tk.Button(root, text="生成新时间", 
                                    command=self.generate_new_time,
                                    font=('Microsoft YaHei', 12),
                                    bg='#4CAF50', fg='white',
                                    padx=20, pady=10)
        self.generate_btn.pack(pady=10)
        
        # 在生成按钮下方添加显示答案按钮
        self.answer_btn = tk.Button(root, text="显示答案", 
                                  command=self.show_answer,
                                  font=('Microsoft YaHei', 12),
                                  bg='#2196F3', fg='white',
                                  padx=20, pady=10)
        self.answer_btn.pack(pady=10)
        
        # 添加用于显示答案的标签
        self.answer_label = tk.Label(root, text="", 
                                   font=('Microsoft YaHei', 14, 'bold'),
                                   fg='#333333')
        self.answer_label.pack(pady=5)
        
        # 初始化时间为12:00
        self.current_hour = 12
        self.current_minute = 0
        
        self.draw_clock()
        
    def draw_clock(self):
        # 清除画布
        self.canvas.delete("all")
        
        # 绘制外圈装饰圆环
        self.canvas.create_oval(45, 45, 355, 355, fill='#FFFFFF', width=2)
        self.canvas.create_oval(50, 50, 350, 350, fill='#FFFFFF', width=3)
        
        # 绘制刻度
        for i in range(60):
            angle = math.radians(i * 6 - 90)
            start_length = 140 if i % 5 == 0 else 145
            x1 = 200 + start_length * math.cos(angle)
            y1 = 200 + start_length * math.sin(angle)
            x2 = 200 + 150 * math.cos(angle)
            y2 = 200 + 150 * math.sin(angle)
            width = 3 if i % 5 == 0 else 1
            self.canvas.create_line(x1, y1, x2, y2, width=width, fill='#333333')
        
        # 绘制数字
        for i in range(1, 13):
            angle = math.radians(i * 30 - 90)
            x = 200 + 120 * math.cos(angle)
            y = 200 + 120 * math.sin(angle)
            # 创建一个小圆作为数字背景
            self.canvas.create_oval(x-15, y-15, x+15, y+15, fill='#FFFFFF', outline='#CCCCCC')
            self.canvas.create_text(x, y, text=str(i), 
                                  font=('Arial', 16, 'bold'), fill='#333333')
        
        # 绘制中心点
        self.canvas.create_oval(195, 195, 205, 205, fill='#333333')
        
        # 绘制时针
        hour_angle = math.radians((self.current_hour % 12 + self.current_minute/60) * 30 - 90)
        hour_x = 200 + 80 * math.cos(hour_angle)
        hour_y = 200 + 80 * math.sin(hour_angle)
        self.canvas.create_line(200, 200, hour_x, hour_y, 
                              width=8, fill='#333333',
                              arrow=tk.LAST, arrowshape=(16, 20, 6))
        
        # 绘制分针
        minute_angle = math.radians(self.current_minute * 6 - 90)
        minute_x = 200 + 110 * math.cos(minute_angle)
        minute_y = 200 + 110 * math.sin(minute_angle)
        self.canvas.create_line(200, 200, minute_x, minute_y, 
                              width=4, fill='#666666',
                              arrow=tk.LAST, arrowshape=(16, 20, 6))
        
    def show_answer(self):
        # 格式化时间显示
        minute_str = "30" if self.current_minute == 30 else "00"
        time_str = f"当前时间是 {self.current_hour}:{minute_str}"
        self.answer_label.config(text=time_str)
    
    def generate_new_time(self):
        # 生成新时间时清除答案
        self.answer_label.config(text="")
        
        # 随机生成整点或半点时间
        self.current_hour = random.randint(1, 12)
        self.current_minute = random.choice([0, 30])
        
        # 重绘时钟
        self.draw_clock()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClockApp(root)
    root.mainloop() 