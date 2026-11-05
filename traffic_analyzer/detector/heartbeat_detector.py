# traffic_analyzer/detector/heartbeat_detector.py
import yaml
import os
import statistics
from scapy.all import IP, TCP, Raw

# 加载配置
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

# 全局告警去重集合
ALERTED_FLOWS = set()

def detect_heartbeat(packets):
    """
    多特征融合心跳检测器（支持告警去重）
    """
    streams = {}
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        if not pkt.haslayer(Raw) or len(pkt[Raw].load) == 0:
            continue
            
        ip = pkt[IP]
        tcp = pkt[TCP]
        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        
        if flow_key not in streams:
            streams[flow_key] = []
        streams[flow_key].append(pkt)

    hb_cfg = CONFIG["detection"]["heartbeat"]
    found = False

    for flow, pkts in streams.items():
        if len(pkts) < hb_cfg["min_samples"]:
            continue
            
        pkts.sort(key=lambda x: x.time)
        times = [p.time for p in pkts]
        sizes = [len(p[Raw].load) for p in pkts]
        
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        avg_size = statistics.mean(sizes)
        std_size = statistics.stdev(sizes) if len(sizes) > 1 else 0
        
        score = 0
        if hb_cfg["min_interval"] <= avg_interval <= hb_cfg["max_interval"]:
            if std_interval < hb_cfg["max_std_dev"]: score += 50
            elif std_interval < 1.0: score += 30
                
        if std_size <= 2: score += 50
        elif std_size <= hb_cfg["max_size_std_dev"]: score += 20
            
        if score >= 70:
            flow_id = str(flow)
            # 告警去重：同一个会话只报一次
            if flow_id not in ALERTED_FLOWS:
                ALERTED_FLOWS.add(flow_id)
                print(f"[!] [告警去重] 发现高置信度 C2 心跳! 方向: {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
                print(f"    -> 平均间隔: {avg_interval:.2f}s, 标准差: {std_interval:.2f}s")
                print(f"    -> 会话持续时间: {times[-1] - times[0]:.2f}s, 首次发现: {pkts[0].time}")
            found = True

    return found