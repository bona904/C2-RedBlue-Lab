# traffic_analyzer/app.py
import os
import time
import yaml
from flask import Flask, request, render_template_string
from scapy.all import rdpcap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from detector.heartbeat_detector import detect_heartbeat
from detector.anomaly_detector import detect_anomaly 
from detector.tls_fingerprint import detect_tls_anomaly # 引入深度 TLS 指纹检测

app = Flask(__name__)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), CONFIG["web"]["upload_folder"])
app.config['MAX_CONTENT_LENGTH'] = CONFIG["web"]["max_file_size_mb"] * 1024 * 1024

# 获取本地已有的样例 pcap
def get_pcap_list():
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        return [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith('.pcap')]
    return []

HTML_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <title>C2 流量分析中心</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f4f7f6; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.05); }
        h1 { text-align: center; border-bottom: 2px solid #eaeaea; padding-bottom: 15px; }
        .upload-area { display: flex; flex-direction: column; align-items: center; gap: 15px; margin: 30px 0; }
        select, input[type=file] { padding: 10px; border: 1px solid #ccc; border-radius: 6px; width: 60%; }
        input[type=submit] { background: #2b6cb0; color: #fff; border: none; padding: 12px 30px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .alert-danger { background: #fed7d7; color: #c53030; padding: 15px; margin: 20px 0; border-radius: 6px; text-align: center; font-weight: bold; }
        .alert-success { background: #c6f6d5; color: #276749; padding: 15px; margin: 20px 0; border-radius: 6px; text-align: center; font-weight: bold; }
        .soc-box { background: #fffaf0; border-left: 4px solid #dd6b20; padding: 15px; margin-top: 20px; }
        .soc-box h4 { color: #dd6b20; margin-top: 0; }
        .chart-container { text-align: center; margin-top: 30px; }
        img { max-width: 100%; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>C2 恶意流量特征分析 Web 平台</h1>
        <form method=post enctype=multipart/form-data>
            <div class="upload-area">
                <select name="sample_file">
                    <option value="">-- 选择系统样例 --</option>
                    {% for pcap in pcap_list %}
                    <option value="{{ pcap }}">{{ pcap }}</option>
                    {% endfor %}
                </select>
                <div>或者手动上传:</div>
                <input type=file name=file>
                <input type=submit value="开始智能分析">
            </div>
        </form>
        
        {% if result %}
            <div class="{{ 'alert-danger' if is_malicious else 'alert-success' }}">{{ result }}</div>
        {% endif %}

        {% if soc_advice %}
            <div class="soc-box">
                <h4>🛡️ SOC 研判与处置建议及证据链：</h4>
                <ul>
                    {% for advice in soc_advice %}
                    <!-- 将换行符替换为 <br>，让证据链排版漂亮 -->
                    <li style="margin-bottom: 10px;">{{ advice | replace('\n', '<br>') | safe }}</li>
                    {% endfor %}
                </ul>
                <!-- 动态日志查看链接 -->
                {% if log_filename %}
                <div style="margin-top: 15px; padding-top: 10px; border-top: 1px dashed #e2e8f0; font-size: 14px;">
                    <span style="color: #dd6b20; font-weight: bold;">📄 提示：</span>
                    已生成完整告警日志，请点击 
                    <a href="/view_log/{{ log_filename }}" target="_blank" style="color: #2b6cb0; text-decoration: underline; font-weight: bold;">此处查看详细日志文件</a>。
                </div>
                {% endif %}
            </div>
        {% endif %}
        
        {% if plot_url %}
            <div class="chart-container"><img src="{{ plot_url }}"></div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    pcap_list = get_pcap_list()
    if request.method == 'POST':
        filepath = None
        file = request.files.get('file')
        
        # 优先处理手动上传，其次处理下拉框选择
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in CONFIG["web"]["allowed_extensions"]:
                return "错误：仅允许上传 .pcap 文件！", 400
            safe_filename = f"upload_{int(time.time())}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(filepath)
        else:
            sample_name = request.form.get('sample_file')
            if sample_name:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], sample_name)

        if filepath and os.path.exists(filepath):
            try:
                # ================= 核心改动 =================
                # 1. 生成唯一的时间戳 ID，用于这次分析的所有产物（日志、图表）
                analysis_id = time.strftime("%Y%m%d_%H%M%S", time.localtime())
                base_name = os.path.basename(filepath)
                # ============================================

                packets = rdpcap(filepath)
                is_malicious = detect_heartbeat(packets)
                
                # 合并所有异常检测结果
                anomalies = detect_anomaly(packets)
                tls_anomalies = detect_tls_anomaly(packets)
                anomalies.extend(tls_anomalies)
                
                # 2. 将完整异常证据写入独立的日志文件
                log_filename = None
                if anomalies:
                    log_filename = f"alerts_{base_name}_{analysis_id}.log"
                    log_file_path = os.path.join(os.path.dirname(__file__), log_filename)
                    
                    with open(log_file_path, "w", encoding="utf-8") as log_file:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        log_file.write(f"==================================================\n")
                        log_file.write(f"分析流水号 (Analysis ID): {analysis_id}\n")
                        log_file.write(f"生成时间: {timestamp}\n")
                        log_file.write(f"分析源文件: {base_name}\n")
                        log_file.write(f"异常总数: {len(anomalies)} 条\n")
                        log_file.write(f"==================================================\n\n")
                        
                        for a in anomalies:
                            log_file.write(f"  - {a.replace(chr(10), ' | ')}\n")
                            
                    print(f"[*] 已将 {len(anomalies)} 条异常证据写入 {log_filename}")

                # 1. 动态构建告警标题
                if is_malicious:
                    result_text = "⚠️ 警告：检测到高置信度 C2 心跳行为！"
                elif anomalies:
                    result_text = "⚠️ 警告：检测到异常网络特征，请查看下方建议！"
                else:
                    result_text = "✅ 安全：未发现异常特征。"
                
                # 2. 动态生成 SOC 处置建议
                soc_advice = []
                if is_malicious:
                    soc_advice.append("【高危】立即隔离受控主机，切断网络连接。")
                    soc_advice.append("【阻断】在边界防火墙封禁该 C2 通信的 IP 和端口。")
                    soc_advice.append("【排查】下发终端杀毒任务，排查是否有免杀木马驻留。")
                
                if anomalies:
                    if len(anomalies) > 10:
                        soc_advice.append(f"【告警聚合】发现大量（共 {len(anomalies)} 条）异常流量特征，可能存在数据外传或端口扫描行为。")
                        for a in anomalies[:3]:
                            soc_advice.append(a)
                        soc_advice.append("... (更多详细证据已折叠)")
                    else:
                        for anomaly in anomalies:
                            if "[异常大包]" in anomaly:
                                soc_advice.append(f"【数据外传】{anomaly}")
                            elif "[异常端口]" in anomaly:
                                soc_advice.append(f"【异常连接】{anomaly}")
                            elif "[HTTP隐蔽隧道]" in anomaly:
                                soc_advice.append(f"【隐蔽隧道】{anomaly}")
                            elif "[TLS" in anomaly:
                                soc_advice.append(anomaly)

                if not soc_advice:
                    soc_advice.append("未发现明显的 C2 通信或数据外传行为。")

                # 3. 生成独立的、不覆盖的图表图片
                times = [p.time for p in packets if p.haslayer('TCP')]
                if len(times) > 1:
                    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                    plt.figure(figsize=(10, 4), dpi=120)
                    plt.plot(intervals, marker='o', linestyle='-', color='#e53e3e' if (is_malicious or anomalies) else '#3182ce')
                    plt.title("TCP 包时间间隔分布", fontname="SimHei")
                    plt.xlabel("Packet Index")
                    plt.ylabel("Interval (Seconds)")
                    plt.grid(True, linestyle='--', alpha=0.6)
                    
                    os.makedirs('static', exist_ok=True)
                    
                    img_filename = f"plot_{analysis_id}.png"
                    img_path = os.path.join('static', img_filename)
                    plt.savefig(img_path)
                    plt.close()
                    
                    # 4. 渲染页面，把动态图片路径和动态日志文件名传进去
                    return render_template_string(
                        HTML_TEMPLATE, 
                        result=result_text, 
                        is_malicious=(is_malicious or bool(anomalies)), 
                        soc_advice=soc_advice, 
                        plot_url=f'/static/{img_filename}',
                        pcap_list=pcap_list, 
                        log_filename=log_filename
                    )
            except Exception as e:
                return render_template_string(HTML_TEMPLATE, result=f"解析失败：{str(e)}", is_malicious=False, pcap_list=pcap_list)
                
    return render_template_string(HTML_TEMPLATE, pcap_list=pcap_list)

# 动态查看日志路由
@app.route('/view_log/<filename>')
def view_log(filename):
    # 安全校验：防止路径穿越漏洞
    if not filename.startswith("alerts_") or not filename.endswith(".log"):
        return "非法请求：文件名不合法。", 400
        
    log_file_path = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(log_file_path):
        with open(log_file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return f"""
        <html>
        <head><meta charset="utf-8"><title>详细告警日志 - {filename}</title></head>
        <body style="background: #f4f7f6; padding: 20px; font-family: 'Consolas', monospace;">
            <div style="max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h2>📄 完整告警证据日志</h2>
                <pre style="white-space: pre-wrap; word-wrap: break-word; color: #2d3748; font-size: 14px; line-height: 1.6;">{content if content else '当前日志文件为空。'}</pre>
                <br>
                <a href="/" style="display: inline-block; padding: 10px 20px; background: #2b6cb0; color: white; text-decoration: none; border-radius: 6px;">返回控制台</a>
            </div>
        </body>
        </html>
        """
    else:
        return "日志文件尚未生成或已被删除。", 404

if __name__ == '__main__':
    app.run(debug=False, port=5000)