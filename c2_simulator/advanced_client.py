# c2_simulator/advanced_client.py
import socket
import time
import base64
import random
import os
from crypto_utils import xor_encrypt
from config import HOST, PORT

def run_advanced():
    while True:
        try:
            sock = socket.create_connection((HOST, PORT), timeout=5)
            print(f"[+] 已连接 {HOST}:{PORT} (泊松心跳 + HTTP伪装 + 随机载荷)")
            while True:
                # 1. 泊松分布（均值 5 秒），打破时间规律
                interval = random.expovariate(1.0 / 5.0)
                
                # 2. 随机载荷填充，打破大小一致性
                base_payload = b"HEARTBEAT"
                padding = os.urandom(random.randint(5, 50))
                raw_data = xor_encrypt(base_payload + padding)
                
                # 3. HTTP 隐蔽隧道伪装
                encoded = base64.b64encode(raw_data).decode()
                http_req = (
                    f"POST /api/v1/update HTTP/1.1\r\n"
                    f"Host: {HOST}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(encoded)}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                    f"data={encoded}"
                )
                
                sock.sendall(http_req.encode())
                print(f"[>] 发送心跳，间隔: {interval:.2f}s, 包长: {len(http_req)}")
                time.sleep(interval)
        except Exception as e:
            print(f"[!] 连接异常: {e}，3 秒后重试")
            time.sleep(3)

if __name__ == "__main__":
    run_advanced()