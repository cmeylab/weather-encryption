import hashlib, pymysql, struct, os, secrets

DB_CONFIG = {
    "host": "localhost", "user": "root", "password": "123456", "charset": "utf8mb4"
}

def init_db():
    conn = pymysql.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS weather_final")
    cur.execute("USE weather_final")
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(20) UNIQUE NOT NULL, rsa_pub TEXT)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS key_log (
        id INT PRIMARY KEY AUTO_INCREMENT, client_ip VARCHAR(50),
        dh_client_pub TEXT, dh_server_pub TEXT)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS transfer_log (
        id INT PRIMARY KEY AUTO_INCREMENT, client_ip VARCHAR(50),
        file_name VARCHAR(100), algorithm VARCHAR(20))''')
    try:
        cur.execute("INSERT INTO users(username) VALUES('legal_user')")
        conn.commit()
    except:
        pass
    cur.close(); conn.close()

# 发送消息函数
def send_msg(sock, data):
    sock.sendall(struct.pack('!I', len(data)) + data)#sendall:保证把所有数据一次性发完,I:无符号整数，固定占 4 个字节
#循环接收函数
def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接断开")
        buf += chunk
    return buf
#接收消息函数
def recv_msg(sock):
    return recv_all(sock, struct.unpack('!I', recv_all(sock, 4))[0])

#素数检测算法，判断大数是否为质数
def _miller_rabin(n, k=20):
    if n < 2: return False
    if n in (2,3): return True
    if n%2==0: return False
    r, d = 0, n-1
    while d%2==0:
        r+=1; d//=2
    for _ in range(k):
        a = secrets.randbelow(n-3)+2
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(r-1):
            x = pow(x,2,n)
            if x == n-1: break
        else: return False
    return True
#生成安全大素数
def _get_prime(bits=512):
    while True:
        p = secrets.randbits(bits) | (1 << bits-1) | 1
        if _miller_rabin(p): return p
# 扩展欧几里得算法，算最大公约数 g
def _extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b//a)*x1, x1
# 求模逆元
def _mod_inverse(e, phi):
    g, x, y = _extended_gcd(e, phi)
    if g != 1:
        raise Exception('逆元不存在')
    return x % phi#防止是负数
 #RSA公钥和私钥
def rsa1024_generate():
    p = _get_prime(512)
    q = _get_prime(512)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = _mod_inverse(e, phi)
    priv_bytes = d.to_bytes(128, 'big') + n.to_bytes(128, 'big')
    pub_bytes = e.to_bytes(4, 'big') + n.to_bytes(128, 'big')
    return priv_bytes, pub_bytes
 #解析RSA私钥
def _parse_rsa_priv(priv_bytes):
    d = int.from_bytes(priv_bytes[:128], 'big')
    n = int.from_bytes(priv_bytes[128:256], 'big')
    return d, n
# 解析RSA公钥
def _parse_rsa_pub(pub_bytes):
    e = int.from_bytes(pub_bytes[:4], 'big')
    n = int.from_bytes(pub_bytes[4:132], 'big')
    return e, n
# RSA签名函数，用私钥对数据签名
def rsa_sign(priv_key, data):
    d, n = _parse_rsa_priv(priv_key)
    hash_int = int.from_bytes(hashlib.sha256(data).digest(), 'big')
    sig_int = pow(hash_int, d, n)
    return sig_int.to_bytes(128, 'big')
# RSA验签函数，用公钥验证签名合法性
def rsa_verify(pub_key, data, signature):
    try:
        e, n = _parse_rsa_pub(pub_key)
        sig_int = int.from_bytes(signature, 'big')
        decrypted_int = pow(sig_int, e, n)
        hash_int = int.from_bytes(hashlib.sha256(data).digest(), 'big')
        return decrypted_int == hash_int
    except:
        return False
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AACAA68FFFFFFFFFFFFFFFF",16)
DH_G = 2
# 生成DH公私钥对
def dh_generate_keys():
    a = secrets.randbits(2048)#私钥
    A = pow(DH_G, a, DH_P)#公钥
    return a.to_bytes(256,'big'), A.to_bytes(256,'big')
# 计算DH共享密钥，生成DES密钥
def dh_get_des_key(priv, peer_pub):
    a = int.from_bytes(priv,'big')
    S = pow(int.from_bytes(peer_pub,'big'), a, DH_P)
    return hashlib.sha256(S.to_bytes(256,'big')).digest()[:8]

# 置换表
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13,
     14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24,
     25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
       60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
       29,21,13,5]

PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
# DES通用比特置换函数
def _permute(block, table, in_bits=64):
    out = 0
    for pos in table:
        bit = (block >> (in_bits - pos)) & 1
        out = (out << 1) | bit
    return out

def _left_rotate(val, shift, bits=28):
    shift %= bits#防止溢出
    return ((val << shift) | (val >> (bits - shift))) & ((1 << bits) - 1)#循环左移
# 生成DES16轮48位子密钥
def _subkeys(key):
    key56 = _permute(key, PC1, 64)
    C = (key56 >> 28) & 0xFFFFFFF
    D = key56 & 0xFFFFFFF
    ks = []
    for s in SHIFT:
        C = _left_rotate(C, s, 28)
        D = _left_rotate(D, s, 28)
        combined = (C << 28) | D
        ks.append(_permute(combined, PC2, 56))
    return ks

def _feistel(R, subkey):
    # 扩展置换 E：32 -> 48
    exp_R = _permute(R, E, 32)
    # 异或子密钥
    x = exp_R ^ subkey
    # S盒替换：48 -> 32
    out = 0
    for i in range(8):
        six_bits = (x >> (42 - i*6)) & 0x3F
        row = ((six_bits >> 5) << 1) | (six_bits & 1)
        col = (six_bits >> 1) & 0xF
        out = (out << 4) | S_BOX[i][row][col]
    # P置换
    return _permute(out, P, 32)
# DES单块加密/解密函数
def _des_block(block, key, decrypt=False):
    block = _permute(block, IP, 64)
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF
    subkeys = _subkeys(key)
    if decrypt:
        subkeys = subkeys[::-1]
    for sk in subkeys:
        L, R = R, L ^ _feistel(R, sk)
    # 最后交换左右
    final = (R << 32) | L
    return _permute(final, IP_INV, 64)
#填充函数，使数据长度为8的倍数
def _pkcs7_pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)
#去填充函数，解密后移除填充
def _pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]
#CBC模式加密，返回 iv + 密文
def des_cbc_encrypt(data, key):
    iv = os.urandom(8)
    prev = int.from_bytes(iv, 'big')
    k = int.from_bytes(key, 'big')
    padded = _pkcs7_pad(data)
    out = iv
    for i in range(0, len(padded), 8):
        block = int.from_bytes(padded[i:i+8], 'big')
        cipher_block = _des_block(block ^ prev, k)
        out += cipher_block.to_bytes(8, 'big')
        prev = cipher_block
    return out
#CBC模式解密，输入 iv+密文，返回明文
def des_cbc_decrypt(data, key):
    iv = data[:8]
    ciphertext = data[8:]
    prev = int.from_bytes(iv, 'big')
    k = int.from_bytes(key, 'big')
    plain = b''
    for i in range(0, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[i:i+8], 'big')
        decrypted = _des_block(block, k, decrypt=True) ^ prev
        plain += decrypted.to_bytes(8, 'big')
        prev = block
    return _pkcs7_unpad(plain)

# 保存DH密钥交换日志到数据库
def save_key_log(ip, c_pub, s_pub):
    conn = pymysql.connect(**DB_CONFIG, database="weather_final")
    cur = conn.cursor()
    cur.execute("INSERT INTO key_log VALUES(null,%s,%s,%s)", (ip,c_pub.hex(),s_pub.hex()))
    conn.commit(); cur.close(); conn.close()
# 保存文件传输日志到数据库
def save_transfer_log(ip, fname):
    conn = pymysql.connect(**DB_CONFIG, database="weather_final")
    cur = conn.cursor()
    cur.execute("INSERT INTO transfer_log VALUES(null,%s,%s,'DES-CBC')", (ip,fname))
    conn.commit(); cur.close(); conn.close()