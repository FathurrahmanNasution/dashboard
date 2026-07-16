import json
import random
from datetime import datetime, timedelta

def generate_mock_suricata_logs():
    # Suricata eve.json alerts
    alerts_eve = []
    # Suricata fast.log alerts
    alerts_fast = []
    
    signatures = [
        {"id": 2001219, "name": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 3},
        {"id": 2027758, "name": "ET MALWARE Active Trojan/Botnet C2 Communication", "category": "A Network Trojan was detected", "severity": 1},
        {"id": 2010935, "name": "ET POLICY Cryptomining Activity Detected (Stratum)", "category": "Policy Violation", "severity": 2},
        {"id": 2035921, "name": "ET EXPLOIT Possible Log4j RCE Attempt", "category": "Web Application Attack", "severity": 1},
        {"id": 2018429, "name": "ET DOS DNS Query Flood", "category": "Attempted Denial of Service", "severity": 2},
    ]

    base_time = datetime.now() - timedelta(hours=1)
    
    ips = ["192.168.1.50", "192.168.1.100", "192.168.1.120", "10.0.0.15", "10.0.0.22"]
    external_ips = ["198.51.100.45", "203.0.113.82", "185.220.101.5", "45.227.254.12", "91.189.91.157"]
    
    for i in range(100):
        sig = random.choice(signatures)
        src_ip = random.choice(ips) if random.random() < 0.8 else random.choice(external_ips)
        dest_ip = random.choice(external_ips) if src_ip in ips else random.choice(ips)
        
        src_port = random.randint(1024, 65535)
        dest_port = random.choice([80, 443, 22, 53, 3389, 8080])
        
        timestamp = base_time + timedelta(seconds=i * random.randint(10, 45))
        timestamp_str = timestamp.isoformat() + "+0700"
        
        # eve.json format
        eve_event = {
            "timestamp": timestamp_str,
            "flow_id": random.randint(10000000, 99999999),
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": "TCP" if dest_port != 53 else "UDP",
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
        alerts_eve.append(eve_event)
        
        # fast.log format
        # Example: 07/16/2026-12:00:00.000000  [**] [1:2001219:1] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 3] {TCP} 192.168.1.50:49213 -> 198.51.100.45:22
        time_fast = timestamp.strftime("%m/%d/%Y-%H:%M:%S.%f")
        fast_line = f"{time_fast}  [**] [1:{sig['id']}:1] {sig['name']} [**] [Classification: {sig['category']}] [Priority: {sig['severity']}] {{TCP}} {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
        alerts_fast.append(fast_line)
        
    with open("eve.json", "w") as f:
        for alert in alerts_eve:
            f.write(json.dumps(alert) + "\n")
            
    with open("fast.log", "w") as f:
        for line in alerts_fast:
            f.write(line + "\n")
            
    print("Generated mock Suricata logs: eve.json and fast.log")

def generate_mock_pcap():
    try:
        from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
    except ImportError:
        print("Scapy is not installed. Mock PCAP generation skipped.")
        return

    print("Generating mock PCAP...")
    packets = []
    base_time = datetime.now() - timedelta(hours=1)
    
    ips = ["192.168.1.50", "192.168.1.100", "192.168.1.120", "10.0.0.15", "10.0.0.22"]
    external_ips = ["198.51.100.45", "203.0.113.82", "185.220.101.5", "45.227.254.12", "91.189.91.157"]
    
    # Generate ~200 packets with varying protocols
    for i in range(300):
        src_ip = random.choice(ips) if random.random() < 0.7 else random.choice(external_ips)
        dest_ip = random.choice(external_ips) if src_ip in ips else random.choice(ips)
        
        proto_choice = random.choice(["TCP", "UDP", "ICMP"])
        
        pkt_time = base_time + timedelta(seconds=i * random.randint(1, 10))
        epoch_time = pkt_time.timestamp()
        
        if proto_choice == "TCP":
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 8080])
            flags = random.choice(["S", "A", "PA", "FA"])
            pkt = Ether()/IP(src=src_ip, dst=dest_ip)/TCP(sport=sport, dport=dport, flags=flags)
        elif proto_choice == "UDP":
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 123])
            pkt = Ether()/IP(src=src_ip, dst=dest_ip)/UDP(sport=sport, dport=dport)
        else: # ICMP
            pkt = Ether()/IP(src=src_ip, dst=dest_ip)/ICMP()
            
        pkt.time = epoch_time
        packets.append(pkt)
        
    wrpcap("test.pcap", packets)
    print("Generated mock PCAP: test.pcap")

def generate_mock_ioc_db():
    iocs = {
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
    with open("ioc_list.json", "w") as f:
        json.dump(iocs, f, indent=4)
    print("Generated mock IoC database: ioc_list.json")

if __name__ == "__main__":
    generate_mock_suricata_logs()
    generate_mock_ioc_db()
    # Try importing scapy and generating PCAP
    generate_mock_pcap()
