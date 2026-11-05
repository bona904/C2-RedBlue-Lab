# traffic_analyzer/evaluate_v2.py
from scapy.all import rdpcap
from detector.heartbeat_detector import detect_heartbeat
import os

def run_evaluation():
    pcap_dir = "../pcaps/"
    test_cases = [
        ("normal_traffic.pcap", False),
        ("fixed_heartbeat.pcap", True),
        ("jitter_heartbeat.pcap", True),
        ("mixed_traffic.pcap", True)
    ]
    
    TP = FP = FN = TN = 0
    for filename, is_malicious in test_cases:
        filepath = os.path.join(pcap_dir, filename)
        if not os.path.exists(filepath): continue
        packets = rdpcap(filepath)
        detected = detect_heartbeat(packets)
        if detected and is_malicious: TP += 1
        elif detected and not is_malicious: FP += 1
        elif not detected and is_malicious: FN += 1
        elif not detected and not is_malicious: TN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print("\n=================================")
    print(f"精确率 (Precision): {precision:.2%}")
    print(f"召回率 (Recall):    {recall:.2%}")
    print(f"F1 分数 (F1-Score): {f1:.2f}")
    print("=================================")

if __name__ == "__main__":
    run_evaluation()