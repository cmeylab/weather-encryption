import socket, pandas as pd, os, threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
from tool import *

class ClientGUI:
    # 1. 初始化（窗口创建时自动执行）
    def __init__(self, root):
        self.root = root
        self.root.title("气象数据传输 - 客户端")
        self.root.geometry("800x600")
        self.selected_file = tk.StringVar(value="未选择文件")
        self.client_socket = None
        self.is_transferring = False
        self._create_widgets()                       # 搭建界面
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # 关闭事件

    # 2. 创建界面控件
    def _create_widgets(self):
        tk.Label(self.root, text="客户端控制台", font=("Arial", 16, "bold")).pack(pady=10)

        # 服务端配置
        config = tk.Frame(self.root)
        config.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(config, text="服务端IP：").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = tk.Entry(config, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        tk.Label(config, text="端口：").grid(row=0, column=2, padx=5, pady=5)
        self.port_entry = tk.Entry(config, width=10)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        self.port_entry.insert(0, "8888")

        # 文件选择
        file_frame = tk.Frame(self.root)
        file_frame.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(file_frame, text="选择文件：").grid(row=0, column=0, padx=5, pady=5)
        tk.Label(file_frame, textvariable=self.selected_file, fg="gray").grid(row=0, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="浏览", command=self.select_file, bg="#2196F3", fg="white").grid(row=0, column=2, padx=5, pady=5)

        # 传输按钮 + 进度条
        self.transfer_btn = tk.Button(self.root, text="连接并传输", command=self.start_transfer, bg="#4CAF50", fg="white")
        self.transfer_btn.pack(pady=10)
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(self.root, variable=self.progress_var, maximum=100).pack(padx=10, pady=5, fill=tk.X)

        # 日志框
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

    # 3. 线程安全的日志输出
    def log(self, msg):
        self.root.after(0, lambda: self._update_log(msg))

    def _update_log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{pd.Timestamp.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    # 4. 选择文件并预览
    def select_file(self):
        path = filedialog.askopenfilename(title="选择CSV文件", filetypes=[("CSV文件", "*.csv")])
        if path:
            self.selected_file.set(path)
            self.log(f"已选文件：{path}")
            try:
                self.log("\n===== 原始数据预览 =====")
                self.log(pd.read_csv(path).head(10).to_string())
            except Exception as e:
                self.log(f"预览失败：{e}")

    # 5. 点击“连接并传输”按钮
    def start_transfer(self):
        if self.is_transferring:
            return
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        file_path = self.selected_file.get()

        if not ip or not port:
            self.log("请填写IP和端口")
            return
        if file_path == "未选择文件":
            self.log("请选择文件")
            return
        try:
            port = int(port)
        except ValueError:
            self.log("端口必须是数字")
            return

        self.is_transferring = True
        self.transfer_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        threading.Thread(target=self.transfer_file, args=(ip, port, file_path), daemon=True).start()

    # 6. 传输线程（认证 + DH协商 + 加密发送文件）
    def transfer_file(self, ip, port, file_path):
        try:
            # 6.1 连接
            self.client_socket = socket.socket()
            self.client_socket.connect((ip, port))
            self.log(f"已连接 {ip}:{port}")

            # 6.2 客户端RSA身份认证
            priv, pub = rsa1024_generate()
            send_msg(self.client_socket, b"legal_user")
            send_msg(self.client_socket, pub)
            send_msg(self.client_socket, rsa_sign(priv, b"client_auth"))

            # 6.3 验证服务端
            server_pub = recv_msg(self.client_socket)
            server_sig = recv_msg(self.client_socket)
            if not rsa_verify(server_pub, b"server_auth", server_sig):
                self.log(" 服务端认证失败")
                self.client_socket.close()
                return
            self.log(" 双向认证通过")

            # 6.4 DH协商
            c_priv, c_pub = dh_generate_keys()
            send_msg(self.client_socket, c_pub)
            des_key = dh_get_des_key(c_priv, recv_msg(self.client_socket))
            self.log(" DH协商完成")

            # 6.5 发送文件元数据
            fname = os.path.basename(file_path)
            fsize = os.path.getsize(file_path)
            send_msg(self.client_socket, fname.encode())
            send_msg(self.client_socket, str(fsize).encode())
            self.log(f"开始传输：{fname} ({fsize}字节)")

            # 6.6 分块加密发送
            sent = 0
            last_progress = -1
            with open(file_path, "rb") as f:
                while sent < fsize and self.is_transferring:
                    data = f.read(1024)
                    send_msg(self.client_socket, des_cbc_encrypt(data, des_key))
                    sent += len(data)
                    progress = int((sent / fsize) * 100)
                    self.root.after(0, self.progress_var.set, progress)
                    if progress // 5 > last_progress:
                        last_progress = progress // 5
                        self.log(f"进度：{progress}%")
            self.log(f" 文件传输完成！")

        except Exception as e:
            self.log(f"传输失败：{e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
            self.is_transferring = False
            self.root.after(0, lambda: self.transfer_btn.config(state=tk.NORMAL))

    # 7. 窗口关闭时的清理
    def on_close(self):
        self.is_transferring = False
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()