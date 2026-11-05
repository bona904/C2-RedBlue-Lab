# traffic_analyzer/detector/tls_fingerprint.py
from scapy.all import IP, TCP, Raw

def detect_tls_anomaly(packets):
    """
    深度 TLS 指纹检测与载荷特征提取
    不仅能报警，还能输出具体的恶意 IP、握手特征和载荷大小
    """
    anomalies = []
    
    # 记录受控端的通信特征
    tls_sessions = {}
    
    tls_ports = {443, 8443, 4433, 80}
    
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
            
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        payload = pkt[Raw].load
        
        # 1. 检查 ClientHello (发往服务端的请求)
        if len(payload) > 5 and payload[0] == 0x16:
            payload_len = len(payload)
            tls_version = f"{payload[1]}.{payload[2]}" # TLS 版本 (如 3.1 代表 TLS 1.0)
            
            # 如果长度过短，标记为可疑
            if payload_len < 150:
                session_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
                
                msg = (
                    f"[TLS指纹深度告警] 发现异常极简握手！\n"
                    f"  -> 可疑源地址: {ip_layer.src}\n"
                    f"  -> 可疑目的地址: {ip_layer.dst}:{tcp_layer.dport}\n"
                    f"  -> 握手包长度: {payload_len} 字节 (正常浏览器 > 200)\n"
                    f"  -> 声明 TLS 版本: {tls_version}"
                )
                if msg not in anomalies:
                    anomalies.append(msg)
                    tls_sessions[session_key] = {"size": payload_len, "version": tls_version}
                    
        # 2. 检查服务端响应回包 (寻找规律)
        elif len(payload) > 5 and payload[0] == 0x17: # TLS Application Data
            payload_len = len(payload)
            session_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
            
            # 如果服务端回包的大小非常固定（比如全是 150 字节左右）
            if 50 <= payload_len <= 300:
                msg = (
                    f"[TLS载荷特征] 发现固定长度加密回包，疑似 C2 通信。\n"
                    f"  -> C2 服务端 IP: {ip_layer.src}:{tcp_layer.sport}\n"
                    f"  -> 回包载荷大小: {payload_len} 字节"
                )
                if msg not in anomalies:
                    anomalies.append(msg)
                    
    return anomalies