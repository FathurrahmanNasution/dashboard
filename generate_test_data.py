import json
import random
from datetime import datetime, timezone, timedelta

def generate_mock_suricata_logs():
    print("Generating high-fidelity mock Suricata logs...")
    events_eve = []
    alerts_fast = []
    
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    
    # Define realistic alert scenarios linking metadata and alerts
    scenarios = [
        {
            "flow_id": 11111111,
            "src_ip": "192.168.1.50",
            "dest_ip": "45.227.254.12",
            "src_port": 50123,
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": "evil-c2-domain.net",
                "rrtype": "A",
                "rdata": "45.227.254.12",
                "answers": [
                    {"rrname": "evil-c2-domain.net", "rrtype": "A", "rdata": "45.227.254.12"}
                ]
            },
            "alert": {
                "signature_id": 2018429,
                "signature": "ET DOS DNS Query Flood for suspicious domain",
                "category": "Attempted Denial of Service",
                "severity": 2
            }
        },
        {
            "flow_id": 22222222,
            "src_ip": "192.168.1.50",
            "dest_ip": "45.227.254.12",
            "src_port": 50124,
            "dest_port": 80,
            "proto": "TCP",
            "http": {
                "hostname": "evil-c2-domain.net",
                "url": "/payload.exe",
                "http_user_agent": "curl/7.68.0",
                "http_method": "GET"
            },
            "alert": {
                "signature_id": 2035921,
                "signature": "ET EXPLOIT Possible Log4j RCE Attempt",
                "category": "Web Application Attack",
                "severity": 1
            }
        },
        {
            "flow_id": 33333333,
            "src_ip": "192.168.1.50",
            "dest_ip": "185.220.101.5",
            "src_port": 50125,
            "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "sni": "malware-c2-server.com",
                "version": "TLS 1.3",
                "subject": "CN=malware-c2-server.com"
            },
            "alert": {
                "signature_id": 2027758,
                "signature": "ET MALWARE Active Trojan/Botnet C2 Communication",
                "category": "A Network Trojan was detected",
                "severity": 1
            }
        }
    ]
    
    # Write scenario events (linked)
    for idx, sc in enumerate(scenarios):
        # 1. Write the metadata event (DNS, HTTP, or TLS)
        timestamp_meta = base_time + timedelta(seconds=idx * 10)
        ts_meta_str = timestamp_meta.isoformat()
        
        meta_event = {
            "timestamp": ts_meta_str,
            "flow_id": sc["flow_id"],
            "src_ip": sc["src_ip"],
            "src_port": sc["src_port"],
            "dest_ip": sc["dest_ip"],
            "dest_port": sc["dest_port"],
            "proto": sc["proto"]
        }
        
        if "dns" in sc:
            meta_event["event_type"] = "dns"
            meta_event["dns"] = sc["dns"]
        elif "http" in sc:
            meta_event["event_type"] = "http"
            meta_event["http"] = sc["http"]
        elif "tls" in sc:
            meta_event["event_type"] = "tls"
            meta_event["tls"] = sc["tls"]
            
        events_eve.append(meta_event)
        
        # 2. Write the Alert event
        timestamp_alert = timestamp_meta + timedelta(seconds=1)
        ts_alert_str = timestamp_alert.isoformat()
        
        alert_event = {
            "timestamp": ts_alert_str,
            "flow_id": sc["flow_id"],
            "event_type": "alert",
            "src_ip": sc["src_ip"],
            "src_port": sc["src_port"],
            "dest_ip": sc["dest_ip"],
            "dest_port": sc["dest_port"],
            "proto": sc["proto"],
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sc["alert"]["signature_id"],
                "rev": 1,
                "signature": sc["alert"]["signature"],
                "category": sc["alert"]["category"],
                "severity": sc["alert"]["severity"]
            }
        }
        events_eve.append(alert_event)
        
        # Fast.log alert lines
        # format: 07/16/2026-12:00:00.000000  [**] [1:2001219:1] ET SCAN ...
        time_fast = timestamp_alert.strftime("%m/%d/%Y-%H:%M:%S.%f")
        fast_line = f"{time_fast}  [**] [1:{sc['alert']['signature_id']}:1] {sc['alert']['signature']} [**] [Classification: {sc['alert']['category']}] [Priority: {sc['alert']['severity']}] {{{sc['proto']}}} {sc['src_ip']}:{sc['src_port']} -> {sc['dest_ip']}:{sc['dest_port']}"
        alerts_fast.append(fast_line)
        
    # Append random alerts to fill database size
    signatures = [
        {"id": 2001219, "name": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 3},
        {"id": 2010935, "name": "ET POLICY Cryptomining Activity Detected (Stratum)", "category": "Policy Violation", "severity": 2},
    ]
    ips = ["192.168.1.100", "192.168.1.120", "10.0.0.15"]
    external_ips = ["203.0.113.82", "91.189.91.157"]
    
    for i in range(50):
        sig = random.choice(signatures)
        src_ip = random.choice(ips)
        dest_ip = random.choice(external_ips)
        src_port = random.randint(1024, 65535)
        dest_port = random.choice([22, 8080])
        
        timestamp = base_time + timedelta(seconds=100 + i * 15)
        ts_str = timestamp.isoformat()
        
        eve_event = {
            "timestamp": ts_str,
            "flow_id": random.randint(44444444, 99999999),
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sig["id"],
                "rev": 1,
                "signature": sig["name"],
                "category": sig["category"],
                "severity": sig["severity"]
            }
        }
        events_eve.append(eve_event)
        
        time_fast = timestamp.strftime("%m/%d/%Y-%H:%M:%S.%f")
        fast_line = f"{time_fast}  [**] [1:{sig['id']}:1] {sig['name']} [**] [Classification: {sig['category']}] [Priority: {sig['severity']}] {{TCP}} {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
        alerts_fast.append(fast_line)
        
    with open("mock_eve.json", "w") as f:
        for alert in events_eve:
            f.write(json.dumps(alert) + "\n")
            
    with open("mock_fast.log", "w") as f:
        for line in alerts_fast:
            f.write(line + "\n")
            
    print("Generated mock Suricata logs successfully.")

def generate_mock_pcap():
    try:
        from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Ether, wrpcap
    except ImportError:
        print("Scapy is not installed. Mock PCAP generation skipped.")
        return

    print("Generating high-fidelity mock PCAP...")
    packets = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    
    # Scenario: DNS Query to malicious domains
    malicious_dns_targets = ["evil-c2-domain.net", "malware-c2-server.com"]
    
    for idx, domain in enumerate(malicious_dns_targets):
        t_pkt = base_time + timedelta(seconds=idx * 2)
        epoch = t_pkt.timestamp()
        
        # 1. DNS Query Packet
        dns_query = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000+idx, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain)
        )
        dns_query.time = epoch
        packets.append(dns_query)
        
        # 2. DNS Response Packet
        dns_response = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=53000+idx) / DNS(
            id=dns_query[DNS].id, qr=1, aa=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, rdata="45.227.254.12")
        )
        dns_response.time = epoch + 0.05
        packets.append(dns_response)
        
    # Standard TCP and UDP packets
    for i in range(150):
        t_pkt = base_time + timedelta(seconds=10 + i * 2)
        epoch = t_pkt.timestamp()
        
        pkt = Ether() / IP(src="192.168.1.50", dst="45.227.254.12") / TCP(sport=random.randint(1024, 65535), dport=443, flags="PA")
        pkt.time = epoch
        packets.append(pkt)
        
    wrpcap("mock_test.pcap", packets)
    print("Generated mock PCAP successfully.")

def generate_mock_ioc_db():
    iocs = {
        "ips": [
            {"ip": "185.220.101.5", "type": "Tor Exit Node", "description": "Known Tor exit node used in credential stuffing", "threat_level": "Medium"},
            {"ip": "45.227.254.12", "type": "Botnet C2", "description": "Active Mirai scanner/C2 node", "threat_level": "High"},
            {"ip": "198.51.100.45", "type": "Spam/Scanner", "description": "IP flagged for active SSH brute forcing attempts", "threat_level": "Low"}
        ],
        "domains": [
            {"domain": "evil-c2-domain.net", "type": "Malware C2", "description": "Domain associated with Cobalt Strike beaconing", "threat_level": "High"},
            {"domain": "malware-c2-server.com", "type": "Cryptominer", "description": "Public Monero mining pool domain", "threat_level": "Medium"}
        ]
    }
    with open("ioc_list.json", "w") as f:
        json.dump(iocs, f, indent=4)
    print("Generated mock IoC database: ioc_list.json")

if __name__ == "__main__":
    generate_mock_suricata_logs()
    generate_mock_ioc_db()
    generate_mock_pcap()
