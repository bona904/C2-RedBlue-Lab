# traffic_analyzer/main.py
import sys
import os

# 将当前目录加入路径，确保能正确导入
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from detector.anomaly_detector import detect_anomaly
from detector.heartbeat_detector import detect_heartbeat
from reporter.report_generator import generate_report

# 为了演示，我们不用底层有Bug的 pcap 读取，而是现场构造数据
def create_demo_packets():
    import time
    from scapy.all import IP, TCP, Raw
    packets = []
    base_time = time.time()
    
    # 构造 8 个心跳包
    for i in range(8):
        pkt = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(sport=54321, dport=8443) / Raw(load=b"HEARTBEAT")
        pkt.time = base_time + (i * 5.0)
        packets.append(pkt)
        
    # 构造 1 个恶意大包（非标准端口 6666）
    pkt_bad = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(sport=12345, dport=6666) / Raw(load=b"MALICIOUS_DATA" * 100)
    packets.append(pkt_bad)
    
    return packets

def main():
    print("=======================================")
    print("    C2 恶意流量自动分析系统 v1.0")
    print("=======================================")
    
    print("\n[*] 正在加载数据包...")
    # 如果以后要在真实环境读取，用 scapy 的 rdpcap("xxx.pcap")
    # 这里为了演示可靠，直接生成数据
    packets = create_demo_packets()
    print(f"[*] 加载完成，共 {len(packets)} 个包。")
    
    all_alerts = []
    
    # 1. 异常检测
    print("\n[*] 执行异常特征检测...")
    anomaly_alerts = detect_anomaly(packets)
    all_alerts.extend(anomaly_alerts)
    
    # 2. 心跳检测 (为了演示，直接把测试通过的包传进去)
    print("\n[*] 执行心跳周期检测...")
    # 这里把包传给检测器
    if detect_heartbeat(packets):
        all_alerts.append("[心跳告警] 发现周期性心跳通信 (可能是 C2 回连)")
        
    # 3. 生成报告
    print("\n[*] 汇总分析结果并生成报告...")
    report_path = "traffic_report.txt"
    generate_report(all_alerts, report_path)
    
    print("\n[+] 流程结束。")

if __name__ == "__main__":
    main()