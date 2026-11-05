# traffic_analyzer/reporter/report_generator.py
import datetime

def generate_report(alerts, output_path="report.txt"):
    """
    将告警列表写入指定的文本文件
    """
    if not alerts:
        alerts = ["[-] 本次分析未发现明显异常。"]
        
    with open(output_path, "w", encoding="utf-8") as f:
        # 写入头部时间
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"========== 流量分析报告 ==========\n")
        f.write(f"生成时间: {now}\n")
        f.write(f"告警总数: {len(alerts)}\n")
        f.write("==================================\n\n")
        
        # 写入具体内容
        for i, alert in enumerate(alerts, 1):
            f.write(f"{i}. {alert}\n")
            
    print(f"[+] 报告已成功生成: {output_path}")