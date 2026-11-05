# c2_simulator/http_client.py
import socket
import time
import base64
from crypto_utils import xor_encrypt
from config import HOST, PORT, HEARTBEAT_INTERVAL

def run_http_tunnel():
    while True:
        try:
            sock = socket.create_connection((HOST, PORT), timeout=5)
            print(f"[+] 已通过 HTTP 伪装连接到 {HOST}:{PORT}")
            
            while True:
                # 1. 把心跳加密并 Base64 编码
                payload = xor_encrypt(b"HEARTBEAT")
                encoded_payload = base64.b64encode(payload).decode()
                
                # 2. 伪装成 HTTP POST 请求
                http_request = (
                    f"POST /api/v1/ping HTTP/1.1\r\n"
                    f"Host: {HOST}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(encoded_payload)}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                    f"data={encoded_payload}"
                )
                
                sock.sendall(http_request.encode())
                print(f"[>] 已发送 HTTP 伪装心跳 ({len(http_request)} 字节)")
                
                # 接收服务端的 HTTP 响应 (忽略内容)
                sock.recv(4096)
                time.sleep(HEARTBEAT_INTERVAL)
                
        except Exception as e:
            print(f"[!] 异常: {e}，3 秒后重试")
            time.sleep(3)

if __name__ == "__main__":
    run_http_tunnel()