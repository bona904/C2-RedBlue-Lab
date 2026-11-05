# c2_simulator/client.py

import socket
import time

from config import HOST, PORT, HEARTBEAT_INTERVAL
from crypto_utils import xor_encrypt


def run():
    while True:
        try:
            sock = socket.create_connection((HOST, PORT), timeout=5)
            print(f"[+] 已连接 {HOST}:{PORT}")

            while True:
                payload = xor_encrypt(b"HEARTBEAT")
                sock.sendall(payload)
                print(f"[>] 已发送 {len(payload)} 字节: {payload.hex()}")
                time.sleep(HEARTBEAT_INTERVAL)

        except Exception as e:
            print(f"[!] 连接异常: {e}，3 秒后重试")
            time.sleep(3)


if __name__ == "__main__":
    run()