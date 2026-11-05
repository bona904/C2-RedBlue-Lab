# traffic_analyzer\capture\pcap_reader.py

from scapy.all import rdpcap, IP, TCP


def read_pcap(file_path):
    """读取 pcap 文件，遍历所有数据包，打印含 TCP 层的包信息。"""
    packets = rdpcap(file_path)

    for packet in packets:
        # 过滤：只处理同时含 IP 层和 TCP 层的包
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            ts = packet.time

            print(
                f"时间戳={ts:.6f} "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            )


if __name__ == "__main__":
    read_pcap("../../pcaps/sample_heartbeat.pcap")