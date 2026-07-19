import os
import json
import re
import csv
import uuid
import copy
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, send_file, make_response, session
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

# Secret key for session management (multi-user isolation)
app.secret_key = os.environ.get('SECRET_KEY', 'aegis-netsec-secret-key-12984')

def get_session_id():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

def get_analysis_filepath():
    sid = get_session_id()
    return os.path.join(app.config['UPLOAD_FOLDER'], f"analysis_{sid}.json")

def get_last_analysis():
    filepath = get_analysis_filepath()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "type": None,
        "filename": None,
        "metrics": {},
        "protocols": [],
        "connections": [],
        "timeline": [],
        "timeline_alerts": [],
        "alerts": [],
        "categories": [],
        "iocs": [],
        "has_alerts": False,
        "truncated": False,
        "warnings": []
    }

def save_analysis(result):
    filepath = get_analysis_filepath()
    try:
        with open(filepath, 'w') as f:
            json.dump(result, f)
    except Exception as e:
        app.logger.error(f"Failed to save analysis: {e}")

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

def match_domain(observed, blacklisted):
    if not observed or not blacklisted:
        return False
    observed = observed.lower().strip('.')
    blacklisted = blacklisted.lower().strip('.')
    if observed == blacklisted:
        return True
    if observed.endswith('.' + blacklisted):
        return True
    return False

def parse_timestamp(ts_str):
    if not ts_str:
        raise ValueError("Timestamp is empty")
    
    # Standardize spaces to T
    if ' ' in ts_str and 'T' not in ts_str:
        ts_str = ts_str.replace(' ', 'T')
        
    try:
        # Standardize timezone offset format if needed (e.g. +0700 -> +07:00)
        if re.search(r'[+-]\d{4}$', ts_str):
            ts_str = ts_str[:-2] + ':' + ts_str[-2:]
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as e1:
        # Fallback to standard formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", 
            "%Y/%m/%d-%H:%M:%S.%f", "%Y/%m/%d-%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y-%H:%M:%S.%f", "%d/%m/%Y-%H:%M:%S",
            "%m/%d/%Y-%H:%M:%S.%f", "%m/%d/%Y-%H:%M:%S",
            "%m/%d/%YT%H:%M:%S.%f", "%m/%d/%YT%H:%M:%S",
            "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"
        ):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue
        raise ValueError(f"Failed to parse timestamp '{ts_str}': {e1}")

def clean_pdf_text(text):
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', errors='replace').decode('latin-1')

def match_iocs(ip_counts, domains_observed=None):
    ioc_db = load_ioc_database()
    matched_iocs = []
    
    # Match IPs
    for ip_entry in ioc_db.get("ips", []):
        ip_addr = ip_entry["ip"]
        if ip_addr in ip_counts:
            matched_iocs.append({
                "ioc": ip_addr,
                "type": ip_entry.get("type", "IP Flagged"),
                "description": ip_entry.get("description", ""),
                "threat_level": ip_entry.get("threat_level", "Medium"),
                "count": ip_counts[ip_addr]
            })
            
    # Match Domains
    if domains_observed:
        for domain_entry in ioc_db.get("domains", []):
            domain_name = domain_entry["domain"].lower()
            for dom, count in domains_observed.items():
                if match_domain(dom, domain_name):
                    matched_iocs.append({
                        "ioc": dom,
                        "type": domain_entry.get("type", "Domain Flagged"),
                        "description": domain_entry.get("description", ""),
                        "threat_level": domain_entry.get("threat_level", "Medium"),
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
    truncated = False
    
    # Single pass to parse packet fields
    with PcapReader(filepath) as pcap_reader:
        for pkt in pcap_reader:
            if len(parsed_packets) >= max_packets:
                truncated = True
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
            "timeline_alerts": [],
            "alerts": [],
            "categories": [],
            "iocs": [],
            "truncated": truncated,
            "warnings": []
        }
        
    start_time = min(p["time"] for p in parsed_packets)
    end_time = max(p["time"] for p in parsed_packets)
    duration = round(end_time - start_time, 2)
    
    # Determine if we should use exact timestamps or dynamic binning
    use_exact = total_packets <= 150
    bin_size = 1.0
    
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
            dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S.%f')[:-3]
        else:
            dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S')
            
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
        "timeline_alerts": [],
        "alerts": [],
        "categories": [],
        "iocs": matched,
        "truncated": truncated,
        "warnings": []
    }


# Suricata EVE JSON parser
def parse_suricata_eve(filepath):
    warnings = []
    events = []
    
    # Try reading as a single JSON array first
    is_parsed = False
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
            for idx, line in enumerate(f, 1):
                if not line.strip():
                    continue
                line_clean = line.strip().rstrip(',').strip()
                if line_clean in ('[', ']'):
                    continue
                try:
                    event = json.loads(line_clean)
                    events.append(event)
                except Exception as e:
                    warnings.append(f"Line {idx} is not valid JSON: {str(e)}")
                    continue
                    
    if not events:
        return {
            "type": "suricata_eve",
            "metrics": {"total_alerts": 0, "unique_signatures": 0, "ioc_count": 0, "severity_1": 0, "severity_2": 0, "severity_3": 0},
            "protocols": [],
            "connections": [],
            "timeline": [],
            "timeline_alerts": [],
            "alerts": [],
            "categories": [],
            "iocs": [],
            "has_alerts": False,
            "truncated": False,
            "warnings": warnings
        }

    alert_flow_ids = set()
    alert_ips = set()
    
    alerts = []
    ip_counts = {}
    dns_queries = {}
    event_types = {}
    connections_raw = {}
    
    severity_counts = {1: 0, 2: 0, 3: 0}
    signature_counts = {}
    category_counts = {}
    
    timeline_raw = {}
    timeline_alerts_raw = {}
    
    event_timestamps = []
    
    # First pass: parse timezone-aware timestamps, build alerts metadata
    for idx, event in enumerate(events, 1):
        event_type = event.get("event_type", "other")
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        
        # Count event types
        etype_upper = event_type.upper()
        event_types[etype_upper] = event_types.get(etype_upper, 0) + 1
        
        # Count IPs for general stats
        if src_ip:
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
        if dest_ip:
            ip_counts[dest_ip] = ip_counts.get(dest_ip, 0) + 1
            
        # Group connections
        if src_ip and dest_ip:
            conn_key = (src_ip, dest_ip)
            connections_raw[conn_key] = connections_raw.get(conn_key, 0) + 1
            
        # DNS query tracking
        if event_type == "dns" and "dns" in event:
            rrname = event["dns"].get("rrname", "").rstrip('.')
            if rrname:
                dns_queries[rrname] = dns_queries.get(rrname, 0) + 1
                
        # Parse timestamp (timezone-aware)
        ts_str = event.get("timestamp", "")
        ts_dt = None
        if ts_str:
            try:
                ts_dt = parse_timestamp(ts_str)
            except Exception as e:
                warn_msg = f"Event #{idx} failed to parse timestamp '{ts_str}': {str(e)}"
                warnings.append(warn_msg)
        else:
            warnings.append(f"Event #{idx} is missing a timestamp field.")
            
        if ts_dt:
            event_timestamps.append(ts_dt.timestamp())
            
        # Build sets of flows and IPs involved in alerts
        if event_type == "alert" and "alert" in event:
            flow_id = event.get("flow_id")
            if flow_id:
                alert_flow_ids.add(flow_id)
            if src_ip:
                alert_ips.add(src_ip)
            if dest_ip:
                alert_ips.add(dest_ip)

    # Determine dynamic bin size
    if event_timestamps:
        start_time = min(event_timestamps)
        end_time = max(event_timestamps)
        duration = round(end_time - start_time, 2)
    else:
        duration = 0
        
    use_exact = len(event_timestamps) <= 150
    bin_size = 1.0
    
    if not use_exact and duration > 0:
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

    # Dynamic IoC extraction cache
    dynamic_iocs = {}

    # Second pass: populate binned timelines, build detailed alerts list, and extract dynamic IoCs
    for idx, event in enumerate(events, 1):
        event_type = event.get("event_type", "other")
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        flow_id = event.get("flow_id")
        
        ts_str = event.get("timestamp", "")
        ts_dt = None
        if ts_str:
            try:
                ts_dt = parse_timestamp(ts_str)
            except Exception:
                pass
                
        time_bin = "N/A"
        if ts_dt:
            t_val = ts_dt.timestamp()
            if use_exact:
                time_bin = round(t_val, 3)
            else:
                time_bin = int(t_val // bin_size) * bin_size
                
        # Populate timelines
        if time_bin != "N/A":
            timeline_raw[time_bin] = timeline_raw.get(time_bin, 0) + 1
            if event_type == "alert":
                timeline_alerts_raw[time_bin] = timeline_alerts_raw.get(time_bin, 0) + 1
                
        # Process alerts
        if event_type == "alert" and "alert" in event:
            alert_data = event["alert"]
            severity = alert_data.get("severity", 3)
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
            
            sig = alert_data.get("signature", "Unknown Signature")
            signature_counts[sig] = signature_counts.get(sig, 0) + 1
            
            category = alert_data.get("category")
            if not category or not str(category).strip():
                category = "N/A"
            else:
                category = str(category).strip()
            category_counts[category] = category_counts.get(category, 0) + 1
            
            alerts.append({
                "id": alert_data.get("signature_id", 0),
                "timestamp": ts_str,
                "signature": sig,
                "category": category,
                "severity": severity,
                "src_ip": src_ip or "N/A",
                "dest_ip": dest_ip or "N/A",
                "src_port": event.get("src_port", "N/A"),
                "dest_port": event.get("dest_port", "N/A"),
                "proto": event.get("proto", "N/A")
            })
            
            # P0-1: Dynamic IP IoC extraction (severity to threat_level mapping)
            threat_level = "Low"
            if severity == 1:
                threat_level = "High"
            elif severity == 2:
                threat_level = "Medium"
                
            if src_ip:
                if src_ip not in dynamic_iocs:
                    dynamic_iocs[src_ip] = {
                        "ioc": src_ip,
                        "type": "Alert Source IP",
                        "description": f"IP triggered alert: {sig}",
                        "threat_level": threat_level,
                        "count": 0
                    }
                dynamic_iocs[src_ip]["count"] += 1
                
            if dest_ip:
                if dest_ip not in dynamic_iocs:
                    dynamic_iocs[dest_ip] = {
                        "ioc": dest_ip,
                        "type": "Alert Destination IP",
                        "description": f"IP received alert: {sig}",
                        "threat_level": threat_level,
                        "count": 0
                    }
                dynamic_iocs[dest_ip]["count"] += 1
                
        # P0-2: Dynamic protocol IoC extraction from associated events
        is_alert_related = False
        if flow_id and flow_id in alert_flow_ids:
            is_alert_related = True
        elif src_ip and src_ip in alert_ips:
            is_alert_related = True
        elif dest_ip and dest_ip in alert_ips:
            is_alert_related = True
            
        if is_alert_related:
            threat_level = "Medium"
            
            # HTTP hostname and URL
            if "http" in event:
                http_data = event["http"]
                hostname = http_data.get("hostname")
                url = http_data.get("url")
                if hostname:
                    if hostname not in dynamic_iocs:
                        dynamic_iocs[hostname] = {
                            "ioc": hostname,
                            "type": "HTTP Hostname",
                            "description": "HTTP Hostname observed in alert flow",
                            "threat_level": threat_level,
                            "count": 0
                        }
                    dynamic_iocs[hostname]["count"] += 1
                if url:
                    if url not in dynamic_iocs:
                        dynamic_iocs[url] = {
                            "ioc": url,
                            "type": "HTTP URL",
                            "description": "HTTP URL observed in alert flow",
                            "threat_level": threat_level,
                            "count": 0
                        }
                    dynamic_iocs[url]["count"] += 1
                    
            # TLS SNI
            if "tls" in event:
                tls_data = event["tls"]
                sni = tls_data.get("sni")
                if sni:
                    if sni not in dynamic_iocs:
                        dynamic_iocs[sni] = {
                            "ioc": sni,
                            "type": "TLS SNI",
                            "description": "TLS SNI observed in alert flow",
                            "threat_level": threat_level,
                            "count": 0
                        }
                    dynamic_iocs[sni]["count"] += 1
                    
            # DNS Rdata
            if "dns" in event:
                dns_data = event["dns"]
                rdata = dns_data.get("rdata")
                if rdata:
                    rdatas = [rdata] if isinstance(rdata, str) else rdata
                    for rd in rdatas:
                        if rd not in dynamic_iocs:
                            dynamic_iocs[rd] = {
                                "ioc": rd,
                                "type": "DNS Rdata",
                                "description": "DNS Rdata observed in alert flow",
                                "threat_level": threat_level,
                                "count": 0
                            }
                        dynamic_iocs[rd]["count"] += 1
                        
                answers = dns_data.get("answers", [])
                for ans in answers:
                    ans_rdata = ans.get("rdata")
                    if ans_rdata:
                        if ans_rdata not in dynamic_iocs:
                            dynamic_iocs[ans_rdata] = {
                                "ioc": ans_rdata,
                                "type": "DNS Rdata",
                                "description": "DNS Answer Rdata observed in alert flow",
                                "threat_level": threat_level,
                                "count": 0
                            }
                        dynamic_iocs[ans_rdata]["count"] += 1

    # Merge dynamic IoCs into a list
    final_iocs = list(dynamic_iocs.values())
    
    # Match against local static threat feed if exists (P2-9 proper domain comparison)
    ioc_db = load_ioc_database()
    for ip_entry in ioc_db.get("ips", []):
        ip_addr = ip_entry["ip"]
        if ip_addr in ip_counts:
            existing = next((i for i in final_iocs if i["ioc"] == ip_addr), None)
            if existing:
                existing["threat_level"] = ip_entry.get("threat_level", existing["threat_level"])
                existing["description"] = f"{existing['description']} | Threat List: {ip_entry.get('description')}"
            else:
                final_iocs.append({
                    "ioc": ip_addr,
                    "type": ip_entry.get("type", "Static Threat IP"),
                    "description": ip_entry.get("description", "IP matched local threat list"),
                    "threat_level": ip_entry.get("threat_level", "Medium"),
                    "count": ip_counts[ip_addr]
                })
                
    if dns_queries:
        for domain_entry in ioc_db.get("domains", []):
            domain_name = domain_entry["domain"].lower()
            for dom, count in dns_queries.items():
                if match_domain(dom, domain_name):
                    existing = next((i for i in final_iocs if i["ioc"] == dom), None)
                    if existing:
                        existing["threat_level"] = domain_entry.get("threat_level", existing["threat_level"])
                        existing["description"] = f"{existing['description']} | Threat List: {domain_entry.get('description')}"
                    else:
                        final_iocs.append({
                            "ioc": dom,
                            "type": domain_entry.get("type", "Static Threat Domain"),
                            "description": domain_entry.get("description", "Domain matched local threat list"),
                            "threat_level": domain_entry.get("threat_level", "Medium"),
                            "count": count
                        })

    # Sort alerts
    alerts = sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
    
    # Format severity distribution
    severity_dist = [{"name": f"Severity {k}", "count": v} for k, v in severity_counts.items() if v > 0]
    
    # Format event types distribution
    event_types_dist = [{"name": k, "count": v} for k, v in event_types.items()]
    
    # Format signatures count (top 10 rules)
    sig_list = [{"name": k, "count": v} for k, v in signature_counts.items()]
    sig_list = sorted(sig_list, key=lambda x: x["count"], reverse=True)[:10]
    
    # Format alert categories count (P1-5)
    category_list = [{"name": k, "count": v} for k, v in category_counts.items()]
    category_list = sorted(category_list, key=lambda x: x["count"], reverse=True)
    
    # Format connections list
    conn_list = []
    for (src, dst), count in connections_raw.items():
        conn_list.append({
            "source": src,
            "destination": dst,
            "count": count
        })
    conn_list = sorted(conn_list, key=lambda x: x["count"], reverse=True)[:15]
    
    # Format timeline (timezone-aware UTC conversion)
    timeline_list = []
    show_ms = use_exact and duration < 5.0
    for t_bin in sorted(timeline_raw.keys()):
        if isinstance(t_bin, (int, float)):
            if show_ms:
                dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S.%f')[:-3]
            else:
                dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S')
        else:
            dt_str = str(t_bin)
            
        timeline_list.append({
            "time": dt_str,
            "count": timeline_raw[t_bin]
        })
        
    timeline_alerts_list = []
    for t_bin in sorted(timeline_alerts_raw.keys()):
        if isinstance(t_bin, (int, float)):
            if show_ms:
                dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S.%f')[:-3]
            else:
                dt_str = datetime.fromtimestamp(t_bin, timezone.utc).strftime('%H:%M:%S')
        else:
            dt_str = str(t_bin)
            
        timeline_alerts_list.append({
            "time": dt_str,
            "count": timeline_alerts_raw[t_bin]
        })
        
    metrics = {
        "total_alerts": len(alerts),  # P1-4: calculated over the full dataset
        "unique_signatures": len(signature_counts),
        "ioc_count": len(final_iocs),
        "severity_1": severity_counts.get(1, 0),
        "severity_2": severity_counts.get(2, 0),
        "severity_3": severity_counts.get(3, 0)
    }
    
    return {
        "type": "suricata_eve",
        "metrics": metrics,
        "protocols": event_types_dist if len(alerts) == 0 else severity_dist,
        "connections": conn_list if len(alerts) == 0 else sig_list,
        "timeline": timeline_list,
        "timeline_alerts": timeline_alerts_list,
        "alerts": alerts,  # Return the full list for caching
        "categories": category_list,
        "iocs": final_iocs,
        "has_alerts": len(alerts) > 0,
        "truncated": False,
        "warnings": warnings
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
    category_counts = {}
    timeline_raw = {}
    warnings = []
    
    # Dynamic IoC extraction
    dynamic_iocs = {}
    
    with open(filepath, 'r', errors='ignore') as f:
        for idx, line in enumerate(f, 1):
            if not line.strip():
                continue
            match = fast_regex.match(line.strip())
            if not match:
                warnings.append(f"Line {idx} does not match fast.log format: {line.strip()}")
                continue
                
            ts_str, sid, sig, category, priority, proto, src_ip, src_port, dest_ip, dest_port = match.groups()
            if not category or not str(category).strip():
                category = "N/A"
            else:
                category = str(category).strip()
            
            # Parse timestamp timezone-aware
            ts_dt = None
            try:
                # Format: 07/16/2026-12:05:12.345678
                ts_dt = parse_timestamp(ts_str.replace('-', 'T'))
            except Exception as e:
                warn_msg = f"Line {idx} failed to parse timestamp '{ts_str}': {str(e)}"
                warnings.append(warn_msg)
                
            time_bin = "N/A"
            if ts_dt:
                time_bin = ts_dt.strftime('%H:%M:%S')
                
            if time_bin != "N/A":
                timeline_raw[time_bin] = timeline_raw.get(time_bin, 0) + 1
                
            severity = int(priority)
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
            
            signature_counts[sig] = signature_counts.get(sig, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            ip_counts[dest_ip] = ip_counts.get(dest_ip, 0) + 1
            
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
            
            # P0-1: Dynamic IP IoC extraction
            threat_level = "Low"
            if severity == 1:
                threat_level = "High"
            elif severity == 2:
                threat_level = "Medium"
                
            if src_ip:
                if src_ip not in dynamic_iocs:
                    dynamic_iocs[src_ip] = {
                        "ioc": src_ip,
                        "type": "Alert Source IP",
                        "description": f"IP triggered alert: {sig}",
                        "threat_level": threat_level,
                        "count": 0
                    }
                dynamic_iocs[src_ip]["count"] += 1
                
            if dest_ip:
                if dest_ip not in dynamic_iocs:
                    dynamic_iocs[dest_ip] = {
                        "ioc": dest_ip,
                        "type": "Alert Destination IP",
                        "description": f"IP received alert: {sig}",
                        "threat_level": threat_level,
                        "count": 0
                    }
                dynamic_iocs[dest_ip]["count"] += 1
                
    # Merge dynamic IoCs into a list
    final_iocs = list(dynamic_iocs.values())
    
    # Match against local static threat feed if exists (P2-9 proper domain comparison)
    ioc_db = load_ioc_database()
    for ip_entry in ioc_db.get("ips", []):
        ip_addr = ip_entry["ip"]
        if ip_addr in ip_counts:
            existing = next((i for i in final_iocs if i["ioc"] == ip_addr), None)
            if existing:
                existing["threat_level"] = ip_entry.get("threat_level", existing["threat_level"])
                existing["description"] = f"{existing['description']} | Threat List: {ip_entry.get('description')}"
            else:
                final_iocs.append({
                    "ioc": ip_addr,
                    "type": ip_entry.get("type", "Static Threat IP"),
                    "description": ip_entry.get("description", "IP matched local threat list"),
                    "threat_level": ip_entry.get("threat_level", "Medium"),
                    "count": ip_counts[ip_addr]
                })

    # Sort alerts
    alerts = sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
    
    # Format severity distribution
    severity_dist = [{"name": f"Severity {k}", "count": v} for k, v in severity_counts.items() if v > 0]
    
    # Format signatures count
    sig_list = [{"name": k, "count": v} for k, v in signature_counts.items()]
    sig_list = sorted(sig_list, key=lambda x: x["count"], reverse=True)[:10]
    
    # Format categories count
    category_list = [{"name": k, "count": v} for k, v in category_counts.items()]
    category_list = sorted(category_list, key=lambda x: x["count"], reverse=True)
    
    # Format timeline
    timeline_list = []
    for t_bin in sorted(timeline_raw.keys()):
        timeline_list.append({
            "time": t_bin,
            "count": timeline_raw[t_bin]
        })
        
    metrics = {
        "total_alerts": len(alerts),  # P1-4: calculated over the full dataset
        "unique_signatures": len(signature_counts),
        "ioc_count": len(final_iocs),
        "severity_1": severity_counts.get(1, 0),
        "severity_2": severity_counts.get(2, 0),
        "severity_3": severity_counts.get(3, 0)
    }
    
    return {
        "type": "suricata_fast",
        "metrics": metrics,
        "protocols": severity_dist,
        "connections": sig_list,
        "timeline": timeline_list,
        "timeline_alerts": timeline_list,  # Identical for fast.log
        "alerts": alerts,  # Return the full list for caching
        "categories": category_list,
        "iocs": final_iocs,
        "has_alerts": True,
        "truncated": False,
        "warnings": warnings
    }


# Main routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if file:
        filename = secure_filename(file.filename)
        if 'suricata.log' in filename.lower() or 'stats.log' in filename.lower() or 'stats' in filename.lower():
            return jsonify({
                "error": "Berkas ini adalah log sistem/statistik Suricata. Silakan unggah berkas 'eve.json' atau 'fast.log' untuk memvisualisasikan lalu lintas jaringan atau alert keamanan."
            }), 400
            
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
            
            result["file_size"] = os.path.getsize(filepath)
            result["filename"] = filename
            save_analysis(result)
            
            # Return sliced alerts for network efficiency (P1-4)
            client_result = copy.deepcopy(result)
            client_result["alerts"] = result.get("alerts", [])[:100]
            
            # Delete file after processing to save disk space
            try:
                os.remove(filepath)
            except Exception:
                pass
                
            return jsonify(client_result)
            
        except Exception as e:
            # Delete file on error
            try:
                os.remove(filepath)
            except Exception:
                pass
            return jsonify({"error": f"Failed to parse file: {str(e)}"}), 500

@app.route('/load_mock', methods=['GET'])
def load_mock():
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
            
        result["file_size"] = os.path.getsize(filepath)
        result["filename"] = filename
        save_analysis(result)
        
        client_result = copy.deepcopy(result)
        client_result["alerts"] = result.get("alerts", [])[:100]
        return jsonify(client_result)
    except Exception as e:
        return jsonify({"error": f"Failed to parse mock file: {str(e)}"}), 500

@app.route('/export/csv', methods=['GET'])
def export_csv():
    analysis_data = get_last_analysis()
    if not analysis_data or not analysis_data.get("type"):
        return "No analysis data available to export", 400
        
    data_type = analysis_data["type"]
    
    # We will generate a CSV response with traffic summary or alerts
    output = make_response()
    output.headers["Content-Disposition"] = f"attachment; filename=report_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output.headers["Content-type"] = "text/csv"
    
    # Create CSV memory buffer
    csv_data = []
    
    if data_type == 'pcap':
        csv_data.append(["=== TRAFFIC METRICS ==="])
        for k, v in analysis_data["metrics"].items():
            csv_data.append([k, v])
        csv_data.append([])
        
        csv_data.append(["=== PROTOCOL DISTRIBUTION ==="])
        csv_data.append(["Protocol", "Count"])
        for p in analysis_data["protocols"]:
            csv_data.append([p["name"], p["count"]])
        csv_data.append([])
        
        csv_data.append(["=== TOP CONNECTIONS ==="])
        csv_data.append(["Source IP", "Destination IP", "Packets", "Bytes"])
        for c in analysis_data["connections"]:
            csv_data.append([c["source"], c["destination"], c["packets"], c["bytes"]])
        csv_data.append([])
        
        csv_data.append(["=== DETECTED IoC MATCHES ==="])
        csv_data.append(["Indicator", "Type", "Description", "Threat Level", "Match Count"])
        for ioc in analysis_data["iocs"]:
            csv_data.append([ioc["ioc"], ioc["type"], ioc["description"], ioc["threat_level"], ioc["count"]])
            
    else: # Suricata logs
        csv_data.append(["=== SURICATA ALERT METRICS ==="])
        for k, v in analysis_data["metrics"].items():
            csv_data.append([k, v])
        csv_data.append([])
        
        csv_data.append(["=== TOP TRIGGERED SIGNATURES ==="])
        csv_data.append(["Signature", "Count"])
        for s in analysis_data["connections"]:
            csv_data.append([s["name"], s["count"]])
        csv_data.append([])
        
        csv_data.append(["=== DETECTED IoC MATCHES ==="])
        csv_data.append(["Indicator", "Type", "Description", "Threat Level", "Match Count"])
        for ioc in analysis_data["iocs"]:
            csv_data.append([ioc["ioc"], ioc["type"], ioc["description"], ioc["threat_level"], ioc["count"]])
        csv_data.append([])
        
        csv_data.append(["=== DETAILED ALERTS ==="])
        csv_data.append(["Timestamp", "Signature ID", "Signature", "Category", "Severity", "Src IP", "Src Port", "Dst IP", "Dst Port", "Proto"])
        # P1-4: Export the FULL alerts list from analysis_data (caching)
        for a in analysis_data["alerts"]:
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
    analysis_data = get_last_analysis()
    if not analysis_data or not analysis_data.get("type"):
        return "No analysis data available to export", 400
        
    if not PDF_AVAILABLE:
        return "PDF generation library (fpdf2) is not available on this server.", 500
        
    data_type = analysis_data["type"]
    filename = analysis_data["filename"]
    
    # Custom PDF Layout using FPDF2
    class PDF(FPDF):
        def header(self):
            self.set_fill_color(24, 28, 41) # Dark Blue theme header background
            self.rect(0, 0, 210, 35, 'F')
            self.set_text_color(255, 255, 255)
            self.set_font('helvetica', 'B', 20)
            self.cell(0, 10, clean_pdf_text('CYBERSECURITY TRAFFIC ANALYSIS REPORT'), border=0, align='L')
            self.ln(8)
            self.set_font('helvetica', 'I', 10)
            self.set_text_color(180, 180, 255)
            self.cell(0, 10, clean_pdf_text(f'File Analyzed: {filename} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'), border=0, align='L')
            self.ln(18)

        def footer(self):
            self.set_y(-15)
            self.set_font('helvetica', 'I', 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, clean_pdf_text(f'Page {self.page_no()}/{{nb}} | Confidential Traffic Report'), border=0, align='C')
            
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('helvetica', '', 11)
    
    # Colors
    pdf.set_text_color(30, 30, 30)
    
    pdf.ln(5)
    # Title
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, clean_pdf_text(f"Analysis Summary ({data_type.upper()})"), ln=True)
    pdf.set_font('helvetica', '', 11)
    pdf.ln(2)
    
    # Metrics Table
    pdf.set_fill_color(230, 230, 250)
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(90, 7, clean_pdf_text("Metric Parameter"), 1, 0, 'L', True)
    pdf.cell(90, 7, clean_pdf_text("Value"), 1, 1, 'L', True)
    pdf.set_font('helvetica', '', 10)
    
    for k, v in analysis_data["metrics"].items():
        pdf.cell(90, 7, clean_pdf_text(str(k).replace('_', ' ').title()), 1, 0, 'L')
        # format numbers nice
        if isinstance(v, int) and v > 1000:
            val_str = f"{v:,}"
        else:
            val_str = str(v)
        pdf.cell(90, 7, clean_pdf_text(val_str), 1, 1, 'L')
        
    pdf.ln(8)
    
    # Indicator of Compromise (IoC) Section
    pdf.set_font('helvetica', 'B', 14)
    # Check if there are malicious matches
    ioc_count = analysis_data["metrics"].get("ioc_count", 0)
    if ioc_count > 0:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, clean_pdf_text(f"!!! DETECTED INDICATORS OF COMPROMISE ({ioc_count}) !!!"), ln=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)
        
        pdf.set_fill_color(255, 230, 230)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 7, clean_pdf_text("IoC Indicator"), 1, 0, 'L', True)
        pdf.cell(30, 7, clean_pdf_text("Type"), 1, 0, 'L', True)
        pdf.cell(20, 7, clean_pdf_text("Threat Level"), 1, 0, 'L', True)
        pdf.cell(75, 7, clean_pdf_text("Description"), 1, 0, 'L', True)
        pdf.cell(15, 7, clean_pdf_text("Matches"), 1, 1, 'C', True)
        pdf.set_font('helvetica', '', 9)
        
        for ioc in analysis_data["iocs"]:
            pdf.cell(40, 7, clean_pdf_text(ioc["ioc"]), 1, 0, 'L')
            pdf.cell(30, 7, clean_pdf_text(ioc["type"]), 1, 0, 'L')
            pdf.cell(20, 7, clean_pdf_text(ioc["threat_level"]), 1, 0, 'L')
            pdf.cell(75, 7, clean_pdf_text(ioc["description"]), 1, 0, 'L')
            pdf.cell(15, 7, clean_pdf_text(str(ioc["count"])), 1, 1, 'C')
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, clean_pdf_text("No known threat intelligence indicators matched in traffic."), ln=True)
        pdf.set_text_color(30, 30, 30)
        
    pdf.ln(8)
    
    # Type-specific Data tables
    if data_type == 'pcap':
        # Protocol Distribution Table
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, clean_pdf_text("Protocol Distribution"), ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(90, 7, clean_pdf_text("Protocol Layer"), 1, 0, 'L', True)
        pdf.cell(90, 7, clean_pdf_text("Packet Count"), 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for p in analysis_data["protocols"]:
            pdf.cell(90, 7, clean_pdf_text(p["name"]), 1, 0, 'L')
            pdf.cell(90, 7, clean_pdf_text(f"{p['count']:,}"), 1, 1, 'R')
            
        pdf.ln(8)
        
        # Connections Table
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, clean_pdf_text("Top Connections by Data Volume"), ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(50, 7, clean_pdf_text("Source IP"), 1, 0, 'L', True)
        pdf.cell(50, 7, clean_pdf_text("Destination IP"), 1, 0, 'L', True)
        pdf.cell(40, 7, clean_pdf_text("Packet Count"), 1, 0, 'R', True)
        pdf.cell(40, 7, clean_pdf_text("Data Volume (Bytes)"), 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for c in analysis_data["connections"]:
            pdf.cell(50, 7, clean_pdf_text(c["source"]), 1, 0, 'L')
            pdf.cell(50, 7, clean_pdf_text(c["destination"]), 1, 0, 'L')
            pdf.cell(40, 7, clean_pdf_text(f"{c['packets']:,}"), 1, 0, 'R')
            pdf.cell(40, 7, clean_pdf_text(f"{c['bytes']:,}"), 1, 1, 'R')
            
    else: # Suricata Logs PDF detail
        # Alert signature Breakdown
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, clean_pdf_text("Top Triggered Rules"), ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(140, 7, clean_pdf_text("Suricata Signature / Rule"), 1, 0, 'L', True)
        pdf.cell(40, 7, clean_pdf_text("Alert Count"), 1, 1, 'R', True)
        pdf.set_font('helvetica', '', 9)
        
        for s in analysis_data["connections"]:
            pdf.cell(140, 7, clean_pdf_text(s["name"]), 1, 0, 'L')
            pdf.cell(40, 7, clean_pdf_text(f"{s['count']:,}"), 1, 1, 'R')
            
        pdf.ln(8)
        
        # Detailed alert table
        pdf.set_font('helvetica', 'B', 12)
        total_alerts_count = len(analysis_data["alerts"])
        pdf.cell(0, 10, clean_pdf_text(f"Recent Alerts Log (Top 15 out of {total_alerts_count} total)"), ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('helvetica', 'B', 8)
        pdf.cell(35, 7, clean_pdf_text("Timestamp"), 1, 0, 'L', True)
        pdf.cell(60, 7, clean_pdf_text("Signature"), 1, 0, 'L', True)
        pdf.cell(15, 7, clean_pdf_text("Severity"), 1, 0, 'C', True)
        pdf.cell(30, 7, clean_pdf_text("Source IP"), 1, 0, 'L', True)
        pdf.cell(30, 7, clean_pdf_text("Destination IP"), 1, 0, 'L', True)
        pdf.cell(10, 7, clean_pdf_text("Port"), 1, 1, 'C', True)
        pdf.set_font('helvetica', '', 7)
        
        for a in analysis_data["alerts"][:15]:
            # truncate timestamp
            ts_short = a["timestamp"].split('+')[0]
            # truncate signature
            sig_short = a["signature"][:35] + "..." if len(a["signature"]) > 38 else a["signature"]
            
            pdf.cell(35, 6, clean_pdf_text(ts_short), 1, 0, 'L')
            pdf.cell(60, 6, clean_pdf_text(sig_short), 1, 0, 'L')
            pdf.cell(15, 6, clean_pdf_text(f"Priority {a['severity']}"), 1, 0, 'C')
            pdf.cell(30, 6, clean_pdf_text(f"{a['src_ip']}:{a['src_port']}"), 1, 0, 'L')
            pdf.cell(30, 6, clean_pdf_text(f"{a['dest_ip']}:{a['dest_port']}"), 1, 0, 'L')
            pdf.cell(10, 6, clean_pdf_text(str(a["proto"])), 1, 1, 'C')
            
    # Save PDF to temporary byte stream
    pdf_output = pdf.output(dest='S')
    
    response = make_response(pdf_output)
    response.headers["Content-Disposition"] = f"attachment; filename=report_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    response.headers["Content-type"] = "application/pdf"
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

