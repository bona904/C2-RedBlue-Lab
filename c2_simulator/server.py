# c2_simulator/server.py

import socket

from config import HOST, PORT


def main():
    # 创建 TCP 服务端 socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许端口复用，避免重启时 address already in use
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[*] C2 服务端已启动，监听 {HOST}:{PORT}")

    while True:
        conn, addr = srv.accept()
        print(f"[+] 新连接来自 {addr}")

        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[-] {addr} 断开连接")
                break
            print(f"[<] 收到 {len(data)} 字节: {data.hex()}")

        conn.close()


if __name__ == "__main__":
    main()