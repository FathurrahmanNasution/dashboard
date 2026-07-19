import os
import sys
import subprocess

# Default paths for Windows installation
SURICATA_EXE = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_YAML = r"C:\Program Files\Suricata\suricata.yaml"

def main():
    print("="*60)
    print(" Aegis NetSec - Suricata Runner on Windows")
    print("="*60)

    # 1. Verify Suricata installation paths
    if not os.path.exists(SURICATA_EXE):
        print(f"[!] Suricata executable not found at: {SURICATA_EXE}")
        print("Please enter the path to suricata.exe manually:")
        user_path = input("> ").strip().strip('"')
        if os.path.exists(user_path):
            exe_path = user_path
        else:
            print("[-] Invalid path. Exiting.")
            sys.exit(1)
    else:
        exe_path = SURICATA_EXE

    if not os.path.exists(SURICATA_YAML):
        yaml_path = os.path.join(os.path.dirname(exe_path), "suricata.yaml")
        if not os.path.exists(yaml_path):
            print("[!] suricata.yaml configuration file not found.")
            print("Please enter the path to suricata.yaml manually:")
            yaml_path = input("> ").strip().strip('"')
            if not os.path.exists(yaml_path):
                print("[-] Invalid config path. Exiting.")
                sys.exit(1)
    else:
        yaml_path = SURICATA_YAML

    # 2. Get the project directory (where this script is cloned/located)
    project_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"[*] Log output directory will be set to: {project_dir}")

    # 3. Retrieve available interfaces using Scapy (installed in venv)
    try:
        from scapy.arch.windows import get_windows_if_list
        win_interfaces = get_windows_if_list()
    except Exception as e:
        print(f"[!] Failed to retrieve network interfaces: {e}")
        win_interfaces = []

    if not win_interfaces:
        print("[!] No interfaces detected. You can enter the interface name, GUID, or IP address manually.")
        interface_choice = input("Interface (e.g. WiFi, Ethernet, or IP): ").strip()
    else:
        print("\nAvailable network interfaces:")
        for idx, iface in enumerate(win_interfaces, 1):
            name = iface.get('name', 'Unknown')
            desc = iface.get('description', 'No description')
            ips = [ip for ip in iface.get('ips', []) if not ip.startswith('fe80::') and ip != '0.0.0.0']
            ip_str = f" | IPs: {', '.join(ips)}" if ips else ""
            print(f"  [{idx}] {name} ({desc}){ip_str}")
        
        print("\nSelect interface number (e.g. 1, 2) or type a custom interface name/IP:")
        choice = input("> ").strip()
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(win_interfaces):
                selected_iface = win_interfaces[choice_idx]
                guid = selected_iface.get('guid', '')
                name = selected_iface.get('name', '')
                if "loopback" in name.lower() or "loopback" in desc.lower():
                    interface_choice = "\\Device\\NPF_Loopback"
                elif guid:
                    interface_choice = f"\\Device\\NPF_{guid}"
                else:
                    interface_choice = name
            else:
                interface_choice = choice
        except ValueError:
            interface_choice = choice

    # Path to local.rules file in the same directory as this script
    local_rules = os.path.join(project_dir, "local.rules")

    # 4. Construct and run the command pointing log output (-l) to project directory
    cmd = [
        exe_path,
        "-c", yaml_path,
        "-i", interface_choice,
        "-l", project_dir
    ]
    
    if os.path.exists(local_rules):
        cmd.extend(["-s", local_rules])

    print("\n" + "="*60)
    print(" Running Suricata...")
    print(f" Command: {' '.join(cmd)}")
    print(f" Logs (eve.json) will be saved in: {project_dir}")
    if os.path.exists(local_rules):
        print(f" Loaded local rules from: {local_rules}")
        print(" [Tip] If you see warnings about missing rule files (e.g. botcc.rules), don't worry!")
        print("       We are loading 'local.rules' which contains built-in detection rules matching")
        print("       our Threat Intel database, plus diagnostic rules for ICMP/HTTP/TLS to verify capturing.")
    print(" Press CTRL+C to stop.")
    print("="*60 + "\n")

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n[*] Suricata stopped by user.")
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Suricata exited with error: {e}")
        print("[Tip] Make sure you are running this terminal as Administrator!")

if __name__ == "__main__":
    main()
