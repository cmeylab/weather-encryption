import socket, pandas as pd, os, threading
import tkinter as tk
from tkinter import scrolledtext
from tool import *

class ServerGUI:
    # 1. 初始化（窗口创建时自动执行）
    def __init__(self, root):
        self.root = root
        self.root.title("气象数据传输 - 服务端")
        self.root.geometry("800x600")
        self.server_socket = None
        self.is_running = False
        self.priv, self.pub = rsa1024_generate()    # 生成服务端固定RSA密钥
        init_db()                                    # 初始化数据库
        os.makedirs("receive", exist_ok=True)        # 创建接收目录
        self._create_widgets()                       # 搭建界面
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # 关闭事件

    # 2. 创建界面控件
    def _create_widgets(self):
        tk.Label(self.root, text="服务端控制台", font=("Arial", 16, "bold")).pack(pady=10)

        self.start_btn = tk.Button(self.root, text="启动服务端", font=("Arial", 12),
                                   command=self.toggle_server, bg="#4CAF50", fg="white")
        self.start_btn.pack(pady=5)
        self.status_label = tk.Label(self.root, text="状态：未启动", font=("Arial", 12), fg="red")
        self.status_label.pack(pady=5)

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

    # 4. 启动/停止服务端（按钮点击）
    def toggle_server(self):
        if not self.is_running:
            # 启动
            self.is_running = True
            self.start_btn.config(text="停止服务端", bg="#f44336")
            self.status_label.config(text="状态：运行中", fg="green")
            self.log("服务端启动中...")
            threading.Thread(target=self._listen, daemon=True).start()
        else:
            # 停止
            self.is_running = False
            if self.server_socket:
                self.server_socket.close()
            self.start_btn.config(text="启动服务端", bg="#4CAF50")
            self.status_label.config(text="状态：已停止", fg="red")
            self.log("服务端已停止")

    # 5. 监听线程（等待客户端连接）
    def _listen(self):
        try:
            self.server_socket = socket.socket()
            self.server_socket.bind(("127.0.0.1", 8888))
            self.server_socket.listen(3)
            self.log("服务端已启动，等待连接...")
            while self.is_running:
                try:
                    conn, addr = self.server_socket.accept()
                    self.log(f"新连接：{addr}")
                    threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
                except socket.error:
                    break
        except Exception as e:
            self.log(f"异常：{e}")
            self.toggle_server()

    # 6. 处理单个客户端（认证 + DH协商 + 接收文件）
    def _handle(self, conn, addr):
        ip = addr[0]
        try:
            # 6.1 验证客户端
            user, pub, sig = recv_msg(conn), recv_msg(conn), recv_msg(conn)
            if user.decode() != "legal_user" or not rsa_verify(pub, b"client_auth", sig):
                self.log("客户端认证失败")
                conn.close()
                return
            self.log("客户端认证通过")

            # 6.2 服务端自证身份
            send_msg(conn, self.pub)
            send_msg(conn, rsa_sign(self.priv, b"server_auth"))

            # 6.3 DH协商
            s_priv, s_pub = dh_generate_keys()
            c_pub = recv_msg(conn)
            send_msg(conn, s_pub)
            des_key = dh_get_des_key(s_priv, c_pub)
            save_key_log(ip, c_pub, s_pub)
            self.log("DH协商完成")

            # 6.4 接收文件元数据
            fname = recv_msg(conn).decode()
            fsize = int(recv_msg(conn).decode())
            path = os.path.join("receive", fname)
            self.log(f"接收：{fname} ({fsize}字节)")

            # 6.5 循环接收并解密数据
            recv_size, last_progress = 0, -1
            with open(path, "wb") as f:
                while recv_size < fsize and self.is_running:
                    raw = des_cbc_decrypt(recv_msg(conn), des_key)
                    f.write(raw)
                    recv_size += len(raw)
                    prog = int((recv_size / fsize) * 100)
                    if prog // 10 > last_progress:
                        last_progress = prog // 10
                        self.log(f"进度：{prog}%")

            # 6.6 预览数据并记录日志
            self.log("\n===== 气象数据预览 =====")
            self.log(pd.read_csv(path).head(10).to_string())
            save_transfer_log(ip, fname)
            self.log(f"{fname} 接收完成！")

        except Exception as e:
            self.log(f"错误：{e}")
        finally:
            conn.close()

    # 7. 窗口关闭时的清理
    def on_close(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()