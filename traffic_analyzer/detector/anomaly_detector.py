# traffic_analyzer/detector/anomaly_detector.py
from scapy.all import IP, TCP, Raw
import re

def detect_anomaly(packets):
    """
    检测异常流量：
    1. 大包（疑似数据外传，载荷 > 1000 字节）
    2. 异常端口（连接非标准端口）
    3. HTTP 隐蔽隧道（检测异常的 POST Base64 载荷）
    """
    anomalies = []
    
    # 定义常见的标准端口（白名单）
    common_ports = {80, 443, 53, 8080, 8443, 22, 21}
    
    for pkt in packets:
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
                
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            # 1. 大包检测
            if pkt.haslayer(Raw):
                payload_len = len(pkt[Raw].load)
                if payload_len > 1000:
                    msg = f"[异常大包] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}，载荷大小: {payload_len} 字节"
                    if msg not in anomalies: # 防止重复记录
                        anomalies.append(msg)
            
            # 2. 异常端口检测 (针对目的端口)
            dst_port = tcp_layer.dport
            if dst_port not in common_ports and dst_port > 1024:
                msg = f"[异常端口] 发现连接非标准端口: {ip_layer.dst}:{dst_port}"
                if msg not in anomalies:
                    anomalies.append(msg)

            # 3. HTTP 隐蔽隧道检测 (针对红队的 HTTP 伪装流量)
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                if isinstance(payload, bytes):
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        # 检测异常的 POST 请求，且 body 中包含超长 Base64 数据
                        if text.startswith('POST') and 'data=' in text:
                            match = re.search(r'data=([a-zA-Z0-9+/=]{50,})', text)
                            if match:
                                msg = f"[HTTP隐蔽隧道] 发现疑似 HTTP Base64 心跳，目的IP: {ip_layer.dst}"
                                if msg not in anomalies:
                                    anomalies.append(msg)
                    except Exception:
                        pass
                    
        except Exception:
            continue
            
    return anomalies

if __name__ == '__main__':
    # 本地简单测试
    from scapy.all import Ether
    print("[*] 测试异常检测...")
    # 模拟一个访问 6666 端口的大包
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=6666) / Raw(load=b"A"*1500)
    res = detect_anomaly([pkt])
    for r in res:
        print(r)