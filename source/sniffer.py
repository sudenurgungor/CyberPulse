from scapy.all import sniff, Raw
from datetime import datetime
import os
import ipaddress
from urllib.parse import unquote_plus
import json
import re

from db import save_blocked_ip_to_db, get_ip_list, save_to_db


MONITORED_NETWORK = ipaddress.ip_network("192.168.56.0/24")
IDS_INTERFACE = "enp0s8"

PORT_SCAN_TIME_WINDOW = 5
HIGH_TRAFFIC_TIME_WINDOW = 5
DUPLICATE_TIME_WINDOW = 15
DEBUG = False

DEFAULT_RULES = {
    "sql_block_threshold": 3,
    "xss_block_threshold": 3,
    "high_traffic_threshold": 40,
    "port_scan_threshold": 5,
    "sql_block_enabled": True,
    "xss_block_enabled": True,
    "high_traffic_block_enabled": True,
    "port_scan_block_enabled": True
}


def load_rules():
    try:
        with open("rules_config.json", "r") as file:
            rules = json.load(file)

        for key, value in DEFAULT_RULES.items():
            if key not in rules:
                rules[key] = value

        return rules

    except Exception as error:
        print("Rules config read error:", error)
        return DEFAULT_RULES.copy()


def refresh_rules():
    global HIGH_TRAFFIC_THRESHOLD
    global PORT_SCAN_THRESHOLD
    global SQL_BLOCK_THRESHOLD
    global XSS_BLOCK_THRESHOLD
    global SQL_BLOCK_ENABLED
    global XSS_BLOCK_ENABLED
    global HIGH_TRAFFIC_BLOCK_ENABLED
    global PORT_SCAN_BLOCK_ENABLED

    rules = load_rules()

    HIGH_TRAFFIC_THRESHOLD = int(rules.get("high_traffic_threshold", 40))
    PORT_SCAN_THRESHOLD = int(rules.get("port_scan_threshold", 5))
    SQL_BLOCK_THRESHOLD = int(rules.get("sql_block_threshold", 3))
    XSS_BLOCK_THRESHOLD = int(rules.get("xss_block_threshold", 3))

    SQL_BLOCK_ENABLED = bool(rules.get("sql_block_enabled", True))
    XSS_BLOCK_ENABLED = bool(rules.get("xss_block_enabled", True))
    HIGH_TRAFFIC_BLOCK_ENABLED = bool(rules.get("high_traffic_block_enabled", True))
    PORT_SCAN_BLOCK_ENABLED = bool(rules.get("port_scan_block_enabled", True))


refresh_rules()

packet_times = {}
port_tracker = {}
attack_counter = {}
blocked_ips = []
last_logged_attacks = {}

WHITELIST = []
BLACKLIST = []


SQL_INJECTION_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'1'\s*=\s*'1",
    r'"?\s*or\s*"1"\s*=\s*"1',
    r"admin'\s*--",
    r"drop\s+table",
    r"delete\s+from",
    r"insert\s+into",
    r"update\s+users",
    r"select\s+\*\s+from",
    r"information_schema",
    r"sleep\s*\(",
    r"benchmark\s*\("
]

XSS_PATTERNS = [
    r"<\s*script",
    r"<\s*/\s*script\s*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<\s*img",
    r"<\s*iframe"
]


def is_duplicate_attack(source_ip, attack_type):
    current_time = datetime.now().timestamp()
    attack_key = (source_ip, attack_type)

    if attack_key in last_logged_attacks:
        last_time = last_logged_attacks[attack_key]

        if current_time - last_time < DUPLICATE_TIME_WINDOW:
            if DEBUG:
                print(f"[DUPLICATE] {attack_type} from {source_ip} ignored")
            return True

    last_logged_attacks[attack_key] = current_time
    return False


def increase_attack_counter(source_ip, attack_type):
    key = (source_ip, attack_type)

    if key not in attack_counter:
        attack_counter[key] = 0

    attack_counter[key] += 1
    return attack_counter[key]


def save_alert(message):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("logs/alerts.txt", "a") as file:
        file.write(f"[{current_time}] {message}\n")


def save_blocked_ip(ip):
    with open("logs/blocked_ips.txt", "a") as file:
        file.write(ip + "\n")


def load_blocked_ips():
    try:
        with open("logs/blocked_ips.txt", "r") as file:
            for line in file:
                ip = line.strip()
                if ip and ip not in blocked_ips:
                    blocked_ips.append(ip)
    except FileNotFoundError:
        open("logs/blocked_ips.txt", "w").close()


def is_in_monitored_network(ip):
    try:
        return ipaddress.ip_address(ip) in MONITORED_NETWORK
    except ValueError:
        return False


def get_payload(packet):
    if packet.haslayer(Raw):
        return packet[Raw].load.decode(errors="ignore")

    try:
        return bytes(packet["TCP"].payload).decode(errors="ignore")
    except Exception:
        return ""


def detect_web_attack(payload):
    decoded_payload = unquote_plus(payload.lower())

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, decoded_payload, re.IGNORECASE):
            return "SQL Injection"

    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded_payload, re.IGNORECASE):
            return "XSS Attack"

    return None


def block_ip_iptables(ip):
    check_command = f"iptables -C INPUT -s {ip} -j DROP > /dev/null 2>&1"
    add_command = f"iptables -A INPUT -s {ip} -j DROP"

    rule_exists = os.system(check_command) == 0

    if not rule_exists:
        os.system(add_command)
        print(f"[FIREWALL] {ip} blocked")
    else:
        print(f"[FIREWALL] {ip} already blocked")


def auto_block_ip(ip, reason):
    print(f"[AUTO BLOCK] {ip} - {reason}")

    block_ip_iptables(ip)

    if ip not in blocked_ips:
        blocked_ips.append(ip)

    save_blocked_ip(ip)
    save_blocked_ip_to_db(ip, reason)
    save_alert(f"[BLOCKED] {ip} - {reason}")


def load_ip_lists():
    global WHITELIST, BLACKLIST

    WHITELIST = [ip[1] for ip in get_ip_list("whitelist")]
    BLACKLIST = [ip[1] for ip in get_ip_list("blacklist")]


def should_block_web_attack(web_attack_type, attack_count):
    if web_attack_type == "SQL Injection":
        return SQL_BLOCK_ENABLED and attack_count >= SQL_BLOCK_THRESHOLD

    if web_attack_type == "XSS Attack":
        return XSS_BLOCK_ENABLED and attack_count >= XSS_BLOCK_THRESHOLD

    return attack_count >= 3


def get_web_threshold(web_attack_type):
    if web_attack_type == "SQL Injection":
        return SQL_BLOCK_THRESHOLD

    if web_attack_type == "XSS Attack":
        return XSS_BLOCK_THRESHOLD

    return 3


def get_dynamic_severity(attack_count, block_threshold):
    if attack_count >= block_threshold:
        return "High"

    if attack_count == block_threshold - 1:
        return "Medium"

    return "Low"


def handle_web_attack(
    web_attack_type,
    source_ip,
    target_ip,
    source_port,
    target_port
):
    refresh_rules()

    attack_count = increase_attack_counter(source_ip, web_attack_type)
    block_threshold = get_web_threshold(web_attack_type)
    severity = get_dynamic_severity(attack_count, block_threshold)

    if should_block_web_attack(web_attack_type, attack_count):
        status = "blocked"
        action_taken = "blocked"
        description = (
            f"{web_attack_type} pattern detected {attack_count} times. "
            f"Threshold reached, IP blocked."
        )

        print(f"[WEB ATTACK] {web_attack_type} detected from {source_ip}")
        print(f"[ACTION] Blocking {source_ip} after {attack_count} attempts")

        save_to_db(
            web_attack_type,
            source_ip,
            target_ip,
            source_port,
            target_port,
            "TCP",
            severity,
            description,
            status,
            action_taken
        )

        auto_block_ip(source_ip, f"{web_attack_type} threshold reached")
        return

    status = "detected"
    action_taken = "monitored"

    if web_attack_type == "SQL Injection" and not SQL_BLOCK_ENABLED:
        description = f"{web_attack_type} pattern detected. Blocking is disabled by rule settings."
    elif web_attack_type == "XSS Attack" and not XSS_BLOCK_ENABLED:
        description = f"{web_attack_type} pattern detected. Blocking is disabled by rule settings."
    else:
        description = (
            f"{web_attack_type} pattern detected. "
            f"Attempt {attack_count}/{block_threshold}. IP is monitored."
        )

    if is_duplicate_attack(source_ip, web_attack_type):
        return

    print(
        f"[WEB ATTACK] {web_attack_type} detected from {source_ip} "
        f"({attack_count}/{block_threshold})"
    )
    print("[ACTION] Monitoring only")

    save_to_db(
        web_attack_type,
        source_ip,
        target_ip,
        source_port,
        target_port,
        "TCP",
        severity,
        description,
        status,
        action_taken
    )


def handle_port_scan(source_ip, target_ip, source_port, target_port):
    current_time = datetime.now().timestamp()

    if source_ip not in port_tracker:
        port_tracker[source_ip] = []

    port_tracker[source_ip].append((target_port, current_time))

    port_tracker[source_ip] = [
        item for item in port_tracker[source_ip]
        if current_time - item[1] <= PORT_SCAN_TIME_WINDOW
    ]

    recent_ports = set(item[0] for item in port_tracker[source_ip])

    if len(recent_ports) > PORT_SCAN_THRESHOLD:
        if is_duplicate_attack(source_ip, "Port Scan"):
            port_tracker[source_ip].clear()
            return

        print(f"[PORT SCAN] Detected from {source_ip}")

        if PORT_SCAN_BLOCK_ENABLED:
            print("[ACTION] Blocking port scan source")

            save_to_db(
                "Port Scan",
                source_ip,
                target_ip,
                source_port,
                target_port,
                "TCP",
                "Medium",
                f"The source IP accessed more than {PORT_SCAN_THRESHOLD} different ports in {PORT_SCAN_TIME_WINDOW} seconds.",
                "blocked",
                "blocked"
            )

            auto_block_ip(source_ip, "Port scan detected")
        else:
            print("[ACTION] Monitoring port scan only")

            save_to_db(
                "Port Scan",
                source_ip,
                target_ip,
                source_port,
                target_port,
                "TCP",
                "Medium",
                "Port scan detected, but blocking is disabled by rule settings.",
                "detected",
                "monitored"
            )

        port_tracker[source_ip].clear()


def handle_high_traffic(source_ip, target_ip, source_port, target_port):
    current_time = datetime.now().timestamp()

    if source_ip not in packet_times:
        packet_times[source_ip] = []

    packet_times[source_ip].append(current_time)

    packet_times[source_ip] = [
        time_value
        for time_value in packet_times[source_ip]
        if current_time - time_value <= HIGH_TRAFFIC_TIME_WINDOW
    ]

    if len(packet_times[source_ip]) > HIGH_TRAFFIC_THRESHOLD:
        if is_duplicate_attack(source_ip, "High Traffic"):
            return

        print(f"[HIGH TRAFFIC] Detected from {source_ip}")

        if HIGH_TRAFFIC_BLOCK_ENABLED:
            print("[ACTION] Blocking high traffic source")

            save_to_db(
                "High Traffic",
                source_ip,
                target_ip,
                source_port,
                target_port,
                "TCP",
                "High",
                f"More than {HIGH_TRAFFIC_THRESHOLD} packets were sent in {HIGH_TRAFFIC_TIME_WINDOW} seconds.",
                "blocked",
                "blocked"
            )

            auto_block_ip(source_ip, "High traffic detected")
        else:
            print("[ACTION] Monitoring high traffic only")

            save_to_db(
                "High Traffic",
                source_ip,
                target_ip,
                source_port,
                target_port,
                "TCP",
                "High",
                "High traffic detected, but blocking is disabled by rule settings.",
                "detected",
                "monitored"
            )


def packet_info(packet):
    refresh_rules()

    if not packet.haslayer("IP"):
        return

    source_ip = packet["IP"].src
    target_ip = packet["IP"].dst

    if source_ip == "192.168.56.112":
        return

    if not packet.haslayer("TCP"):
        return

    if not (
        is_in_monitored_network(source_ip)
        or is_in_monitored_network(target_ip)
    ):
        return

    if source_ip in WHITELIST:
        return

    if source_ip in BLACKLIST:
        auto_block_ip(source_ip, "Manual blacklist")
        return

    source_port = packet["TCP"].sport
    target_port = packet["TCP"].dport
    payload = get_payload(packet)

    # 1) Web attack detection
    if payload:
        web_attack_type = detect_web_attack(payload)

        if web_attack_type:
            handle_web_attack(
                web_attack_type,
                source_ip,
                target_ip,
                source_port,
                target_port
            )
            return

    # 2) Time-based port scan detection
    handle_port_scan(source_ip, target_ip, source_port, target_port)

    # 3) Time-based high traffic detection
    handle_high_traffic(source_ip, target_ip, source_port, target_port)


def start_sniffer():
    refresh_rules()

    print("Traffic monitoring started!")

    load_blocked_ips()
    load_ip_lists()

    print("Whitelist:", WHITELIST)
    print("Blacklist:", BLACKLIST)
    print("Loaded blocked IPs:", blocked_ips)
    print("SQL block threshold:", SQL_BLOCK_THRESHOLD)
    print("XSS block threshold:", XSS_BLOCK_THRESHOLD)
    print("High traffic threshold:", HIGH_TRAFFIC_THRESHOLD)
    print("Port scan threshold:", PORT_SCAN_THRESHOLD)
    print("Port scan time window:", PORT_SCAN_TIME_WINDOW)
    print("High traffic time window:", HIGH_TRAFFIC_TIME_WINDOW)
    print("SQL block enabled:", SQL_BLOCK_ENABLED)
    print("XSS block enabled:", XSS_BLOCK_ENABLED)
    print("High traffic block enabled:", HIGH_TRAFFIC_BLOCK_ENABLED)
    print("Port scan block enabled:", PORT_SCAN_BLOCK_ENABLED)

    sniff(
        prn=packet_info,
        store=False,
        iface=IDS_INTERFACE
    )


if __name__ == "__main__":
    start_sniffer()