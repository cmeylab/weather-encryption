# Weather Encryption — 气象数据加密传输系统

基于 TCP Socket 的气象雷达数据传输与加密系统，实现 **双向身份认证 + 端到端数据加密**。适用于对气象雷达 CSV 数据进行安全可靠的网络传输。

## 功能特性

| 功能 | 技术实现 |
|------|----------|
| 双向身份认证 | RSA-1024 数字签名，客户端与服务端互相验证身份 |
| 会话密钥协商 | Diffie-Hellman 密钥交换，基于 2048 位安全素数 |
| 数据加密 | DES-CBC 模式加密，PKCS7 填充 |
| 图形界面 | Tkinter 双端 GUI，实时日志与进度显示 |
| 传输日志 | MySQL 记录密钥协商日志与文件传输记录 |
| 数据预览 | 接收端自动预览 CSV 数据前 10 行 |

## 系统架构

```
┌─────────────────┐         TCP Socket          ┌─────────────────┐
│   Client GUI    │ ──────────────────────────►  │   Server GUI    │
│  (client.py)    │   1. RSA 双向认证             │  (server.py)    │
│                 │   2. DH 密钥协商              │                 │
│  气象雷达 CSV    │   3. DES-CBC 加密传输         │  receive/ 目录   │
└─────────────────┘                              └─────────────────┘
                                                        │
                                                        ▼
                                                 ┌─────────────────┐
                                                 │    MySQL DB     │
                                                 │  weather_final  │
                                                 └─────────────────┘
```

## 快速开始

### 环境要求

- Python 3.10+
- MySQL 8.0+（用于记录传输日志）
- 依赖安装

```bash
pip install -r requirements.txt
```

### 配置数据库

确保 MySQL 运行后，修改 `tool.py` 中的数据库配置：

```python
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "your_password",
    "charset": "utf8mb4"
}
```

> **安全提示**：生产环境建议通过环境变量或 `.env` 文件配置数据库密码，请勿硬编码。

### 启动服务端

```bash
python server.py
```

GUI 启动后点击 **「启动服务端」**，监听 `127.0.0.1:8888`。

### 启动客户端

```bash
python client.py
```

1. 填写服务端 IP 和端口（默认 `127.0.0.1:8888`）
2. 点击 **「浏览」** 选择要发送的 CSV 文件
3. 点击 **「连接并传输」**

## 加密流程

```
客户端                               服务端
  │                                    │
  ├── 发送 legal_user + RSA公钥 + 签名 ──►  验证客户端身份
  │◄── 发送 RSA公钥 + 签名 ─────────────┤  服务端自证身份
  │                                    │
  ├── 发送 DH公钥 ────────────────────►  协商会话密钥
  │◄── 发送 DH公钥 ────────────────────┤
  │  共享密钥 = SHA256(DH共享密钥)[:8]  │
  │                                    │
  ├── DES-CBC 加密发送 CSV 数据 ────────►  解密并保存
  │                                    │
```

## 项目结构

```
weather-encryption/
├── server.py          # 服务端 GUI + 接收逻辑
├── client.py          # 客户端 GUI + 发送逻辑
├── tool.py            # 加密算法 + 网络协议 + 数据库操作
├── radar_data.csv     # 示例气象雷达数据
├── requirements.txt   # Python 依赖
└── README.md          # 项目文档
```

## 算法说明

- **RSA-1024**：基于 Miller-Rabin 素数检测 + 扩展欧几里得算法，SHA256 哈希签名
- **Diffie-Hellman**：使用 RFC 3526 2048-bit MODP Group，SHA256 派生 64-bit DES 密钥
- **DES-CBC**：标准 Feistel 网络，16 轮迭代，8 个 S-Box，PKCS7 填充，随机 IV

## 注意事项

- 本系统使用 DES 算法，仅适用于教学与实验场景
- 数据库密码请勿提交到版本控制系统
- `receive/` 目录用于存放接收文件，已加入 `.gitignore`

## 许可证

MIT License
