# pcaps/dataset_generator.py
from scapy.all import IP, TCP, Raw, wrpcap
import random
import time
import os

def generate_normal_traffic(count=20):
    """生成正常的网页浏览流量（杂乱无章，包大小不一）"""
    packets = []
    base_time = time.time()
    for i in range(count):
        # 随机大小 100-800 字节，随机时间间隔 0.1-2.0 秒
        pkt = IP(src="192.168.1.100", dst="104.18.32.7") / TCP(sport=random.randint(40000, 60000), dport=443) / Raw(load=b"A" * random.randint(100, 800))
        pkt.time = base_time + random.uniform(0.1, 2.0)
        packets.append(pkt)
    return packets

def generate_fixed_heartbeat(count=10):
    """生成固定 5 秒的恶意心跳流量"""
    packets = []
    base_time = time.time()
    for i in range(count):
        # 载荷固定 9 字节，时间严格间隔 5 秒
        pkt = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(sport=54321, dport=8443) / Raw(load=b"HEARTBEAT")
        pkt.time = base_time + (i * 5.0)
        packets.append(pkt)
    return packets

def generate_jitter_heartbeat(count=10):
    """生成带随机抖动（±0.3s）的对抗心跳流量（模拟红队规避检测）"""
    packets = []
    base_time = time.time()
    for i in range(count):
        jitter = random.uniform(-0.3, 0.3) # 随机抖动 ±0.3秒
        pkt = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(sport=54321, dport=8443) / Raw(load=b"HEARTBEAT")
        pkt.time = base_time + (i * 5.0) + jitter
        packets.append(pkt)
    return packets

if __name__ == "__main__":
    print("[*] 正在生成测试 pcap 数据集...")
    
    # 1. 正常流量
    normal = generate_normal_traffic()
    wrpcap("normal_traffic.pcap", normal)
    print("[+] 已生成: normal_traffic.pcap")
    
    # 2. 固定心跳
    fixed = generate_fixed_heartbeat()
    wrpcap("fixed_heartbeat.pcap", fixed)
    print("[+] 已生成: fixed_heartbeat.pcap")
    
    # 3. 抖动心跳
    jitter = generate_jitter_heartbeat()
    wrpcap("jitter_heartbeat.pcap", jitter)
    print("[+] 已生成: jitter_heartbeat.pcap")
    
    # 4. 混杂流量（正常 + 固定心跳）
    mixed = generate_normal_traffic(10) + generate_fixed_heartbeat(5)
    mixed.sort(key=lambda x: x.time)
    wrpcap("mixed_traffic.pcap", mixed)
    print("[+] 已生成: mixed_traffic.pcap")
    
    print("[*] 所有测试数据生成完毕！可以去跑检测器了。")