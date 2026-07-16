import os
import json
import re
import csv
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, make_response
from werkzeug.utils import secure_filename
import pandas as pd

# Load Scapy components
try:
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Load PDF components
try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global variables to cache the last parsed result
LAST_ANALYSIS = {
    "type": None,          # 'pcap' or 'suricata_eve' or 'suricata_fast'
    "filename": None,
    "metrics": {},
    "protocols": [],
    "connections": [],
    "timeline": [],
    "alerts": [],
    "iocs": []
}

# Default Local IoC database in case ioc_list.json is missing
DEFAULT_IOC_DB = {
    "ips": [
        {"ip": "185.220.101.5", "type": "Tor Exit Node", "description": "Known Tor exit node used in credential stuffing", "threat_level": "Medium"},
        {"ip": "45.227.254.12", "type": "Botnet C2", "description": "Active Mirai scanner/C2 node", "threat_level": "High"},
        {"ip": "198.51.100.45", "type": "Spam/Scanner", "description": "IP flagged for active SSH brute forcing attempts", "threat_level": "Low"}
    ],
    "domains": [
        {"domain": "malware-c2-server.com", "type": "Malware C2", "description": "Domain associated with Cobalt Strike beaconing", "threat_level": "High"},
        {"domain": "pool.minexmr.com", "type": "Cryptominer", "description": "Public Monero mining pool domain", "threat_level": "Medium"}
    ]
}

def load_ioc_database():
    ioc_path = os.path.join(os.path.dirname(__file__), 'ioc_list.json')
    if os.path.exists(ioc_path):
        try:
            with open(ioc_path, 'r') as f:
                return json.load(f)
        except Exception:
            return DEFAULT_IOC_DB
    return DEFAULT_IOC_DB

def match_iocs(ip_counts, domains_observed=None):
    ioc_db = load_ioc_database()
    matched_iocs = []
    
    # Match IPs
    for ip_entry in ioc_db.get("ips", []):
        ip_addr = ip_entry["ip"]
        if ip_addr in ip_counts:
            matched_iocs.append({
                "ioc": ip_addr,
                "type": ip_entry["type"],
                "description": ip_entry["description"],
                "threat_level": ip_entry["threat_level"],
                "count": ip_counts[ip_addr]
            })
            
    # Match Domains
    if domains_observed:
        for domain_entry in ioc_db.get("domains", []):
            domain_name = domain_entry["domain"].lower()
            for dom, count in domains_observed.items():
                if domain_name in dom.lower():
                    matched_iocs.append({
                        "ioc": dom,
                        "type": domain_entry["type"],
                        "description": domain_entry["description"],
                        "threat_level": domain_entry["threat_level"],
                        "count": count
                    })
                    
    return matched_iocs

# PCAP Parsing logic
def parse_pcap(filepath):
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is not installed on this server.")
        
    total_packets = 0
    total_bytes = 0
    
    protocols = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "DNS": 0,
        "Other": 0
    }
    
    connections = {}
    ip_counts = {}
    dns_queries = {}
    timeline_raw = {}
    
    # Process up to 50,000 packets for performance reasons
    max_packets = 50000
    parsed_packets = []
    
    # Single pass to parse packet fields
    with PcapReader(filepath) as pcap_reader:
        for pkt in pcap_reader:
            if len(parsed_packets) >= max_packets:
                break
                
            pkt_time = float(pkt.time)
            pkt_len = len(pkt)
            
            is_ip = False
            src = None
            dst = None
            proto_type = "Other"
            dns_qname = None
            
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src = ip_layer.src
                dst = ip_layer.dst
                is_ip = True
                
                if pkt.haslayer(TCP):
                    proto_type = "TCP"
                elif pkt.haslayer(UDP):
                    proto_type = "UDP"
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        proto_type = "DNS"
                        dns_qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                elif pkt.haslayer(ICMP):
                    proto_type = "ICMP"
                    
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
                src = ip_layer.src
                dst = ip_layer.dst
                is_ip = True
                
                if pkt.haslayer(TCP):
                    proto_type = "TCP"
                elif pkt.haslayer(UDP):
                    proto_type = "UDP"
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        proto_type = "DNS"
                        dns_qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                elif "ICMPv6" in pkt or pkt.haslayer(ICMP):
                    proto_type = "ICMP"
                    
            elif pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                src = arp_layer.psrc
                dst = arp_layer.pdst
                is_ip = True
                
            parsed_packets.append({
                "time": pkt_time,
                "len": pkt_len,
                "is_ip": is_ip,
                "src": src,
                "dst": dst,
                "proto": proto_type,
                "dns_qname": dns_qname
            })
            
    total_packets = len(parsed_packets)
    if total_packets == 0:
        return {
            "type": "pcap",
            "metrics": {"total_packets": 0, "total_bytes": 0, "duration_seconds": 0, "avg_packet_size": 0, "unique_ips": 0, "ioc_count": 0},
            "protocols": [],
            "connections": [],
            "timeline": [],
            "alerts": [],
            "iocs": []
        }
        
    start_time = min(p["time"] for p in parsed_packets)
    end_time = max(p["time"] for p in parsed_packets)
    duration = round(end_time - start_time, 2)
    
    # Determine if we should use exact timestamps or dynamic binning
    use_exact = total_packets <= 150
    
    if not use_exact:
        if duration <= 10.0:
            bin_size = 0.5
        elif duration <= 60.0:
            bin_size = 1.0
        elif duration <= 300.0:
            bin_size = 5.0
        elif duration <= 1800.0:
            bin_size = 10.0
        elif duration <= 7200.0:
            bin_size = 30.0
        else:
            bin_size = 60.0
            
    # Process packet stats
    for p in parsed_packets:
        total_bytes += p["len"]
        
        # Protocol counting
        protocols[p["proto"]] = protocols.get(p["proto"], 0) + 1
        if p["proto"] == "DNS" and p["dns_qname"]:
            dns_queries[p["dns_qname"]] = dns_queries.get(p["dns_qname"], 0) + 1
            
        # Grouping packets for timeline
        if use_exact:
            time_bin = round(p["time"], 3)
        else:
            time_bin = int(p["time"] // bin_size) * bin_size
            
        if time_bin not in timeline_raw:
            timeline_raw[time_bin] = {"packets": 0, "bytes": 0}
        timeline_raw[time_bin]["packets"] += 1
        timeline_raw[time_bin]["bytes"] += p["len"]
        
        # Connection tracking
        if p["is_ip"]:
            conn_key = (p["src"], p["dst"])
            if conn_key not in connections:
                connections[conn_key] = {"packets": 0, "bytes": 0}
            connections[conn_key]["packets"] += 1
            connections[conn_key]["bytes"] += p["len"]
            
            ip_counts[p["src"]] = ip_counts.get(p["src"], 0) + 1
            ip_counts[p["dst"]] = ip_counts.get(p["dst"], 0) + 1
            
    # Format protocol distribution
    proto_dist = [{"name": k, "count": v} for k, v in protocols.items() if v > 0]
    
    # Format connections
    conn_list = []
    for (src, dst), stats in connections.items():
        conn_list.append({
            "source": src,
            "destination": dst,
            "packets": stats["packets"],
            "bytes": stats["bytes"]
        })
    conn_list = sorted(conn_list, key=lambda x: x["bytes"], reverse=True)[:15]
    
    # Format timeline
    timeline_list = []
    show_ms = use_exact and duration < 5.0
    
    for t_bin in sorted(timeline_raw.keys()):
        if show_ms:
            dt_str = datetime.fromtimestamp(t_bin).strftime('%H:%M:%S.%f')[:-3]
        else:
            dt_str = datetime.fromtimestamp(t_bin).strftime('%H:%M:%S')
            
        timeline_list.append({
            "time": dt_str,
            "packets": timeline_raw[t_bin]["packets"],
            "bytes": timeline_raw[t_bin]["bytes"]
        })
        
    # Match IoCs
    matched = match_iocs(ip_counts, dns_queries)
    
    metrics = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "avg_packet_size": round(total_bytes / total_packets, 2) if total_packets > 0 else 0,
        "unique_ips": len(ip_counts),
        "ioc_count": len(matched)
    }
    
    return {
        "type": "pcap",
        "metrics": metrics,
        "protocols": proto_dist,
        "connections": conn_list,
        "timeline": timeline_list,
        "alerts": [],
        "iocs": matched
    }

# Suricata EVE JSON parser
def parse_suricata_eve(filepath):
    alerts = []
    ip_counts = {}
    severity_counts = {1: 0, 2: 0, 3: 0}
    signature_counts = {}
    timeline_raw = {}
    
    total_alerts = 0
    
    # Try reading as a single JSON array first
    is_parsed = False
    events = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            data = json.load(f)
            if isinstance(data, list):
                events = data
                is_parsed = True
            elif isinstance(data, dict):
                events = [data]
                is_parsed = True
    except Exception:
        pass
        
    # If not a single JSON array, read line-by-line (standard line-delimited eve.json)
    if not is_parsed:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                # Skip leading/trailing commas or brackets in case it was a semi-formatted array
                line_clean = line.strip().rstrip(',').strip()
                if line_clean in ('[', ']'):
                    continue
                try:
                    event = json.loads(line_clean)
                    events.append(event)
                except Exception:
                    continue
                    
    # Now process the list of events
    for event in events:
        try:
            if event.get("event_type") == "alert":
                total_alerts += 1
                alert_data = event["alert"]
                severity = alert_data.get("severity", 3)
                if severity not in severity_counts:
                    severity_counts[severity] = 0
                severity_counts[severity] += 1
                
                sig = alert_data.get("signature", "Unknown Signature")
                signature_counts[sig] = signature_counts.get(sig, 0) + 1
                
                src_ip = event.get("src_ip", "N/A")
                dest_ip = event.get("dest_ip", "N/A")
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                ip_counts[dest_ip] = ip_counts.get(dest_ip, 0) + 1
                
                # Time handling
                ts_str = event.get("timestamp", "")
                ts_clean = ts_str.split('+')[0].split('.')[0]
                try:
                    ts_dt = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
                    time_bin = ts_dt.strftime('%H:%M:%S')
                except Exception:
                    time_bin = ts_clean[-8:] if len(ts_clean) >= 8 else "N/A"
                    
                if time_bin not in timeline_raw:
                    timeline_raw[time_bin] = 0
                timeline_raw[time_bin] += 1
                
                alerts.append({
                    "id": alert_data.get("signature_id", 0),
                    "timestamp": ts_str,
                    "signature": sig,
                    "category": alert_data.get("category", "N/A"),
                    "severity": severity,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": event.get("src_port", "N/A"),
                    "dest_port": event.get("dest_port", "N/A"),
                    "proto": event.get("proto", "N/A")
                })
        except Exception:
            continue
                
    # Sort alerts by timestamp descending
    alerts = sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
    
    # Format severity distribution
    severity_dist = [{"name": f"Severity {k}", "count": v} for k, v in severity_counts.items() if v > 0]
    
    # Format signatures count
    sig_list = [{"name": k, "count": v} for k, v in signature_counts.items()]
    sig_list = sorted(sig_list, key=lambda x: x["count"], reverse=True)[:10]
    
    # Format timeline
    timeline_list = []
    for t_bin in sorted(timeline_raw.keys()):
        timeline_list.append({
            "time": t_bin,
            "count": timeline_raw[t_bin]
        })
        
    # Match IoCs
    matched = match_iocs(ip_counts)
    
    metrics = {
        "total_alerts": total_alerts,
        "unique_signatures": len(signature_counts),
        "ioc_count": len(matched),
        "severity_1": severity_counts.get(1, 0),
        "severity_2": severity_counts.get(2, 0),
        "severity_3": severity_counts.get(3, 0)
    }
    
    return {
        "type": "suricata_eve",
        "metrics": metrics,
        "protocols": severity_dist, # map to severity distribution
        "connections": sig_list,    # map to top rules
        "timeline": timeline_list,
        "alerts": alerts[:100],     # Return top 100 alerts for performance
        "iocs": matched
    }

# Suricata fast.log parser
def parse_suricata_fast(filepath):
    # Log sample: 07/16/2026-12:05:12.345678  [**] [1:2001219:1] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 3] {TCP} 192.168.1.50:49213 -> 198.51.100.45:22
    # Regex: date_time [**] [gid:sid:rev] signature [**] [Classification: classification] [Priority: priority] {proto} src -> dst
    fast_regex = re.compile(
        r'^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+(.*?)\s+\[\*\*\]\s+\[Classification:\s+(.*?)\]\s+\[Priority:\s+(\d+)\]\s+{(\w+)}\s+(\S+):(\d+)\s+->\s+(\S+):(\d+)'
    )
    
    alerts = []
    ip_counts = {}
    severity_counts = {1: 0, 2: 0, 3: 0}
    signature_counts = {}
    timeline_raw = {}
    
    total_alerts = 0
    
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            if not line.strip():
                continue
            match = fast_regex.match(line.strip())
            if match:
                total_alerts += 1
                ts_str, sid, sig, category, priority, proto, src_ip, src_port, dest_ip, dest_port = match.groups()
                
                severity = int(priority)
                if severity not in severity_counts:
                    severity_counts[severity] = 0
                severity_counts[severity] += 1
                
                signature_counts[sig] = signature_counts.get(sig, 0) + 1
                
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                ip_counts[dest_ip] = ip_counts.get(dest_ip, 0) + 1
                
                # Extract time for timeline binning
                # 07/16/2026-12:05:12.345678 -> 12:05:12
                time_bin = ts_str.split('-')[1].split('.')[0]
                if time_bin not in timeline_raw:
                    timeline_raw[time_bin] = 0
                timeline_raw[time_bin] += 1
                
                alerts.append({
                    "id": int(sid),
                    "timestamp": ts_str,
                    "signature": sig,
                    "category": category,
                    "severity": severity,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": int(src_port),
                    "dest_port": int(dest_port),
                    "proto": proto
                })
                
    # Sort alerts
    alerts = sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
    
    # Format severity distribution
    severity_dist = [{"name": f"Severity {k}", "count": v} for k, v in severity_counts.items() if v > 0]
    
    # Format signatures count
    sig_list = [{"name": k, "count": v} for k, v in signature_counts.items()]
    sig_list = sorted(sig_list, key=lambda x: x["count"], reverse=True)[:10]
    
    # Format timeline
    timeline_list = []
    for t_bin in sorted(timeline_raw.keys()):
        timeline_list.append({
            "time": t_bin,
            "count": timeline_raw[t_bin]
        })
        
    # Match IoCs
    matched = match_iocs(ip_counts)
    
    metrics = {
        "total_alerts": total_alerts,
        "unique_signatures": len(signature_counts),
        "ioc_count": len(matched),
        "severity_1": severity_counts.get(1, 0),
        "severity_2": severity_counts.get(2, 0),
        "severity_3": severity_counts.get(3, 0)
    }
    
    return {
        "type": "suricata_fast",
        "metrics": metrics,
        "protocols": severity_dist, # map to severity distribution
        "connections": sig_list,    # map to top rules
        "timeline": timeline_list,
        "alerts": alerts[:100],     # Return top 100 alerts
        "iocs": matched
    }

# Main routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    global LAST_ANALYSIS
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Detect file type
            if filename.endswith('.pcap') or filename.endswith('.pcapng'):
                if not SCAPY_AVAILABLE:
                    return jsonify({"error": "Server does not have Scapy installed to parse PCAP files."}), 500
                result = parse_pcap(filepath)
            elif filename.endswith('.json') or 'eve' in filename:
                result = parse_suricata_eve(filepath)
            elif filename.endswith('.log') or 'fast' in filename:
                result = parse_suricata_fast(filepath)
            else:
                # Try parsing as JSON first, then as fast.log text
                try:
                    result = parse_suricata_eve(filepath)
                except Exception:
                    try:
                        result = parse_suricata_fast(filepath)
                    except Exception:
                        return jsonify({"error": "Unsupported file format. Please upload .pcap, eve.json, or fast.log"}), 400
            
            result["filename"] = filename
            LAST_ANALYSIS = result
            
            # Delete file after processing to save disk space
            try:
                os.remove(filepath)
            except Exception:
                pass
                
            return jsonify(result)
            
        except Exception as e:
            # Delete file on error
            try:
                os.remove(filepath)
            except Exception:
                pass
            return jsonify({"error": f"Failed to parse file: {str(e)}"}), 500

@app.route('/load_mock', methods=['GET'])
def load_mock():
    global LAST_ANALYSIS
    filename = request.args.get('file')
    if not filename:
        return jsonify({"error": "No file name provided"}), 400
        
    filename = os.path.basename(filename)
    filepath = os.path.join(os.path.abspath(os.path.dirname(__file__)), filename)
    
    if not os.path.exists(filepath):
        return jsonify({"error": f"Mock file {filename} not found on server."}), 404
        
    try:
        if filename.endswith('.pcap'):
            result = parse_pcap(filepath)
        elif filename.endswith('.json'):
            result = parse_suricata_eve(filepath)
        elif filename.endswith('.log'):
            result = parse_suricata_fast(filepath)
        else:
            return jsonify({"error": "Unsupported file format for mock loading"}), 400
            
        result["filename"] = filename
        LAST_ANALYSIS = result
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Failed to parse mock file: {str(e)}"}), 500

@app.route('/export/csv', methods=['GET'])
def export_csv():
    global LAST_ANALYSIS
    if not LAST_ANALYSIS["type"]:
        return "No analysis data available to export", 400
        
    data_type = LAST_ANALYSIS["type"]
    
    # We will generate a CSV response with traffic summary or alerts
    output = make_response()
    output.headers["Content-Disposition"] = f"attachment; filename=report_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output.headers["Content-type"] = "text/csv"
    
    # Create CSV memory buffer
    csv_data = []
    
    if data_type == 'pcap':
        csv_data.append(["=== TRAFFIC METRICS ==="])
        for k, v in LAST_ANALYSIS["metrics"].items():
            csv_data.append([k, v])
        csv_data.append([])
        
        csv_data.append(["=== PROTOCOL DISTRIBUTION ==="])
        csv_data.append(["Protocol", "Count"])
        for p in LAST_ANALYSIS["protocols"]:
            csv_data.append([p["name"], p["count"]])
        csv_data.append([])
        
        csv_data.append(["=== TOP CONNECTIONS ==="])
        csv_data.append(["Source IP", "Destination IP", "Packets", "Bytes"])
        for c in LAST_ANALYSIS["connections"]:
            csv_data.append([c["source"], c["destination"], c["packets"], c["bytes"]])
        csv_data.append([])
        
        csv_data.append(["=== DETECTED IoC MATCHES ==="])
        csv_data.append(["Indicator", "Type", "Description", "Threat Level", "Match Count"])
        for ioc in LAST_ANALYSIS["iocs"]:
            csv_data.append([ioc["ioc"], ioc["type"], ioc["description"], ioc["threat_level"], ioc["count"]])
            
    else: # Suricata logs
        csv_data.append(["=== SURICATA ALERT METRICS ==="])
        for k, v in LAST_ANALYSIS["metrics"].items():
            csv_data.append([k, v])
        csv_data.append([])
        
        csv_data.append(["=== TOP TRIGGERED SIGNATURES ==="])
        csv_data.append(["Signature", "Count"])
        for s in LAST_ANALYSIS["connections"]:
            csv_data.append([s["name"], s["count"]])
        csv_data.append([])
        
        csv_data.append(["=== DETECTED IoC MATCHES ==="])
        csv_data.append(["Indicator", "Type", "Description", "Threat Level", "Match Count"])
        for ioc in LAST_ANALYSIS["iocs"]:
            csv_data.append([ioc["ioc"], ioc["type"], ioc["description"], ioc["threat_level"], ioc["count"]])
        csv_data.append([])
        
        csv_data.append(["=== DETAILED ALERTS ==="])
        csv_data.append(["Timestamp", "Signature ID", "Signature", "Category", "Severity", "Src IP", "Src Port", "Dst IP", "Dst Port", "Proto"])
        for a in LAST_ANALYSIS["alerts"]:
            csv_data.append([
                a["timestamp"], a["id"], a["signature"], a["category"], 
                a["severity"], a["src_ip"], a["src_port"], a["dest_ip"], a["dest_port"], a["proto"]
            ])
            
    # Write to response content
    import io
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerows(csv_data)
    output.data = si.getvalue().encode('utf-8')
    
    return output

@app.route('/export/pdf', methods=['GET'])
def export_pdf():
    global LAST_ANALYSIS
    if not LAST_ANALYSIS["type"]:
        return "No analysis data available to export", 400
        
    if not PDF_AVAILABLE:
        return "PDF generation library (fpdf2) is not available on this server.", 500
        
    data_type = LAST_ANALYSIS["type"]
    filename = LAST_ANALYSIS["filename"]
    
    # Custom PDF Layout using FPDF2
    class PDF(FPDF):
        def header(self):
            self.set_fill_color(24, 28, 41) # Dark Blue theme header background
            self.rect(0, 0, 210, 35, 'F')
            self.set_text_color(255, 255, 255)
            self.set_font('helvetica', 'B', 20)
            self.cell(0, 10, 'CYBERSECURITY TRAFFIC ANALYSIS REPORT', border=0, align='L')
            self.ln(8)
            self.set_font('helvetica', 'I', 10)
            self.set_text_color(180, 180, 255)
            self.cell(0, 10, f'File Analyzed: {filename} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', border=0, align='L')
            self.ln(18)

        def footer(self):
            self.set_y(-15)
            self.set_font('helvetica', 'I', 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | Confidential Traffic Report', border=0, align='C')
            
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('helvetica', '', 11)
    
    # Colors
    pdf.set_text_color(30, 30, 30)
    
    pdf.ln(5)
    # Title
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, f"Analysis Summary ({data_type.upper()})", ln=True)
    pdf.set_font('helvetica', '', 11)
    pdf.ln(2)
    
    # Metrics Table
    pdf.set_fill_color(230, 230, 250)
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(90, 7, "Metric Parameter", 1, 0, 'L', True)
    pdf.cell(90, 7, "Value", 1, 1, 'L', True)
    pdf.set_font('helvetica', '', 10)
    
    for k, v in LAST_ANALYSIS["metrics"].items():
        pdf.cell(90, 7, str(k).replace('_', ' ').title(), 1, 0, 'L')
        # format numbers nice
        if isinstance(v, int) and v > 1000:
            val_str = f"{v:,}"
        else:
            val_str = str(v)
        pdf.cell(90, 7, val_str, 1, 1, 'L')
        
    pdf.ln(8)
    
    # Indicator of Compromise (IoC) Section
    pdf.set_font('helvetica', 'B', 14)
    # Check if there are malicious matches
    ioc_count = LAST_ANALYSIS["metrics"].get("ioc_count", 0)
    if ioc_count > 0:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, f"!!! DETECTED INDICATORS OF COMPROMISE ({ioc_count}) !!!", ln=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)
        
        pdf.set_fill_color(255, 230, 230)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 7, "IoC Indicator", 1, 0, 'L', True)
        pdf.cell(30, 7, "Type", 1, 0, 'L', True)
        pdf.cell(20, 7, "Threat Level", 1, 0, 'L', True)
        pdf.cell(75, 7, "Description", 1, 0, 'L', True)
        pdf.cell(15, 7, "Matches", 1, 1, 'C', True)
        pdf.set_font('helvetica', '', 9)
        
        for ioc in LAST_ANALYSIS["iocs"]:
            pdf.cell(40, 7, ioc["ioc"], 1, 0, 'L')
            pdf.cell(30, 7, ioc["type"], 1, 0, 'L')
            pdf.cell(20, 7, ioc["threat_level"], 1, 0, 'L')
            pdf.cell(75, 7, ioc["description"], 1, 0, 'L')
            pdf.cell(15, 7, str(ioc["count"]), 1, 1, 'C')
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "No known threat intelligence indicators matched in traffic.", ln=True)
        pdf.set_text_color(30, 30, 30)
        
    pdf.ln(8)
    
    # Type-specific Data tables
    if data_type == 'pcap':
        # Protocol Distribution Table
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, "Protocol Distribution", ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(90, 7, "Protocol Layer", 1, 0, 'L', True)
        pdf.cell(90, 7, "Packet Count", 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for p in LAST_ANALYSIS["protocols"]:
            pdf.cell(90, 7, p["name"], 1, 0, 'L')
            pdf.cell(90, 7, f"{p['count']:,}", 1, 1, 'R')
            
        pdf.ln(8)
        
        # Connections Table
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, "Top Connections by Data Volume", ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(50, 7, "Source IP", 1, 0, 'L', True)
        pdf.cell(50, 7, "Destination IP", 1, 0, 'L', True)
        pdf.cell(40, 7, "Packet Count", 1, 0, 'R', True)
        pdf.cell(40, 7, "Data Volume (Bytes)", 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for c in LAST_ANALYSIS["connections"]:
            pdf.cell(50, 7, c["source"], 1, 0, 'L')
            pdf.cell(50, 7, c["destination"], 1, 0, 'L')
            pdf.cell(40, 7, f"{c['packets']:,}", 1, 0, 'R')
            pdf.cell(40, 7, f"{c['bytes']:,}", 1, 1, 'R')
            
    else: # Suricata Logs PDF detail
        # Alert signature Breakdown
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, "Top Triggered Rules", ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(140, 7, "Suricata Signature / Rule", 1, 0, 'L', True)
        pdf.cell(40, 7, "Alert Count", 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for s in LAST_ANALYSIS["connections"]:
            pdf.cell(140, 7, s["name"], 1, 0, 'L')
            pdf.cell(40, 7, f"{s['count']:,}", 1, 1, 'R')
            
        pdf.ln(8)
        
        # Detailed alert table
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, "Recent Alerts Log (Top 15)", ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 8)
        pdf.cell(35, 7, "Timestamp", 1, 0, 'L', True)
        pdf.cell(60, 7, "Signature", 1, 0, 'L', True)
        pdf.cell(15, 7, "Severity", 1, 0, 'C', True)
        pdf.cell(30, 7, "Source IP", 1, 0, 'L', True)
        pdf.cell(30, 7, "Destination IP", 1, 0, 'L', True)
        pdf.cell(10, 7, "Port", 1, 1, 'C', True)
        pdf.set_font('helvetica', '', 7)
        
        for a in LAST_ANALYSIS["alerts"][:15]:
            # truncate timestamp
            ts_short = a["timestamp"].split('+')[0]
            # truncate signature
            sig_short = a["signature"][:35] + "..." if len(a["signature"]) > 38 else a["signature"]
            
            pdf.cell(35, 6, ts_short, 1, 0, 'L')
            pdf.cell(60, 6, sig_short, 1, 0, 'L')
            pdf.cell(15, 6, f"Priority {a['severity']}", 1, 0, 'C')
            pdf.cell(30, 6, f"{a['src_ip']}:{a['src_port']}", 1, 0, 'L')
            pdf.cell(30, 6, f"{a['dest_ip']}:{a['dest_port']}", 1, 0, 'L')
            pdf.cell(10, 6, str(a["proto"]), 1, 1, 'C')
            
    # Save PDF to temporary byte stream
    pdf_output = pdf.output(dest='S')
    
    response = make_response(pdf_output)
    response.headers["Content-Disposition"] = f"attachment; filename=report_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    response.headers["Content-type"] = "application/pdf"
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
