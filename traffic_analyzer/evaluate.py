# traffic_analyzer/evaluate.py
import sys
import os
from scapy.all import rdpcap
from detector.heartbeat_detector import detect_heartbeat

# 用控制台输出重定向来捕获检测器的打印（简单粗暴）
import io
import contextlib

def run_test(pcap_file, expected_has_heartbeat):
    print(f"\n[测试] 正在分析: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[-] 找不到文件 {pcap_file}，请先在 pcaps 目录下运行 dataset_generator.py")
        return False
        
    # 捕获 stdout，防止干扰输出
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        detected = detect_heartbeat(packets)
        
    # 判定结果
    if detected == expected_has_heartbeat:
        print(f"  -> [正确] 期望: {expected_has_heartbeat}, 实际: {detected}")
        return True
    else:
        print(f"  -> [错误] 期望: {expected_has_heartbeat}, 实际: {detected}")
        return False

if __name__ == "__main__":
    # 确保你在 traffic_analyzer 目录下运行
    pcap_dir = "../pcaps/"
    
    tests = [
        ("normal_traffic.pcap", False),
        ("fixed_heartbeat.pcap", True),
        ("jitter_heartbeat.pcap", True), # 抖动心跳我们期望它还能检出来，或者故意设为True测漏报
        ("mixed_traffic.pcap", True)
    ]
    
    correct = 0
    for pcap, expected in tests:
        if run_test(pcap_dir + pcap, expected):
            correct += 1
            
    print("\n=================================")
    print(f"量化评估结果: 准确率 = {correct / len(tests) * 100:.2f}%")
    print("=================================")