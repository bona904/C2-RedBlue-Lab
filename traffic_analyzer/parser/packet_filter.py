# traffic_analyzer\capture\packet_filter.py

from scapy.all import rdpcap, IP, TCP


def filter_traffic(packets, target_port=None, target_ip=None):
    """按目标端口 / 目标 IP 过滤数据包。

    参数：
        packets     : scapy 数据包列表（rdpcap 返回值）
        target_port : 目标端口（int 或 None），匹配源端口或目的端口任一
        target_ip   : 目标 IP（str 或 None），匹配源 IP 或目的 IP 任一

    返回：
        过滤后的数据包列表（list）

    匹配规则：
        - 只处理同时含 IP 层和 TCP 层的包
        - target_port 和 target_ip 都为 None 时，返回全部含 IP+TCP 的包
        - 两者都传时，按"同时满足"（AND）过滤
    """
    result = []

    for packet in packets:
        # 只处理同时含 IP 层和 TCP 层的包
        if IP not in packet or TCP not in packet:
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # 端口匹配：源或目的任一相等即算命中
        if target_port is not None:
            if src_port != target_port and dst_port != target_port:
                continue

        # IP 匹配：源或目的任一相等即算命中
        if target_ip is not None:
            if src_ip != target_ip and dst_ip != target_ip:
                continue

        result.append(packet)

    return result


if __name__ == "__main__":
    # 读取样本 pcap
    packets = rdpcap("../../pcaps/sample_heartbeat.pcap")

    # 过滤端口 8443（C2 心跳常用端口，见 c2_simulator/config.py）
    filtered = filter_traffic(packets, target_port=8443)

    print(f"[*] 原始包数: {len(packets)}")
    print(f"[*] 过滤后包数（端口 8443）: {len(filtered)}")

    for p in filtered:
        print(
            f"时间戳={p.time:.6f} "
            f"{p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport}"
        )