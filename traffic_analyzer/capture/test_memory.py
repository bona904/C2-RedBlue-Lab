# traffic_analyzer/capture/test_memory.py
import time
from scapy.all import IP, TCP, Raw
from heartbeat_detector import detect_heartbeat

def generate_fake_packets():
    """模拟生成 10 个带有 payload 的心跳包，间隔 5 秒"""
    packets = []
    base_time = time.time()
    
    for i in range(10):
        # 构造 IP/TCP 包，加上 Raw 层（代表有数据载荷）
        pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=54321, dport=8443) / Raw(load=b"HEARTBEAT")
        # 强行修改包的时间戳（每隔 5 秒）
        pkt.time = base_time + (i * 5.0)
        packets.append(pkt)
        
    return packets

if __name__ == '__main__':
    print("[*] 正在生成模拟的心跳数据包...")
    fake_packets = generate_fake_packets()
    
    print("[*] 将数据送入 heartbeat_detector 进行检测...\n")
    result = detect_heartbeat(fake_packets)
    
    if result:
        print("\n[+] 测试通过！成功识别出心跳规律。")
    else:
        print("\n[-] 测试失败。检测器未能识别出心跳。")