import time
import statistics
from collections import defaultdict, deque
from scapy.all import IP, ICMP, TCP, UDP, Raw
from .logger_setup import logger
from .payload_analyzer import detect_malicious_payload
from .config import THRESHOLD_MULTIPLIER, HIGH_TRAFFIC_PORTS, ICMP_THRESHOLD, PAYLOAD_THRESHOLD

# Tracking variables
packet_count_per_ip = defaultdict(int)
packet_rate_per_ip = defaultdict(lambda: deque(maxlen=10))
start_time = time.time()

def calculate_packet_rate(ip_src):
    """Calculates the packet rate per IP, based on recent intervals."""
    current_time = time.time()
    elapsed_time = current_time - start_time

    if elapsed_time == 0:
        return 0, 0

    # Update the packet rate per second
    rate = packet_count_per_ip[ip_src] / elapsed_time
    packet_rate_per_ip[ip_src].append(rate)

    # Calculate the average of the latest rates
    avg_rate = statistics.mean(packet_rate_per_ip[ip_src])
    return rate, avg_rate

def log_alert(subject, body):
    """Logs alerts to the rotating log file and prints them to the console."""
    log_message = f"{subject} - {body}"
    logger.info(log_message)
    print(f"[ALERT] {log_message}")

def analyze_packet(packet):
    """Analyzes packets to detect advanced network anomalies."""
    global packet_count_per_ip

    if IP not in packet:
        return

    ip_src = packet[IP].src
    packet_count_per_ip[ip_src] += 1

    current_rate, avg_rate = calculate_packet_rate(ip_src)

    # Detect traffic spikes
    if avg_rate > 0 and current_rate > avg_rate * THRESHOLD_MULTIPLIER:
        alert_subject = f"ALERT: Traffic spike from {ip_src}"
        alert_body = (f"IP {ip_src} has a traffic rate of {current_rate:.2f} packets/sec, "
                      f"which is significantly higher than the average of {avg_rate:.2f} packets/sec.")
        log_alert(alert_subject, alert_body)

    # Detect ICMP traffic (e.g., ping flood attack)
    if ICMP in packet:
        if packet_count_per_ip[ip_src] > ICMP_THRESHOLD:
            alert_subject = f"ALERT: Possible ICMP attack (ping flood) from {ip_src}"
            alert_body = f"IP {ip_src} has sent more than {ICMP_THRESHOLD} ICMP packets."
            log_alert(alert_subject, alert_body)

    # Detect unusual TCP/UDP traffic on sensitive or uncommon ports
    if TCP in packet or UDP in packet:
        dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
        if dport not in HIGH_TRAFFIC_PORTS:
            alert_subject = f"ALERT: Traffic on uncommon port {dport} from {ip_src}"
            alert_body = f"Traffic detected from IP {ip_src} to port {dport}, which is unusual."
            log_alert(alert_subject, alert_body)

        # Payload analysis for unusual behavior
        if Raw in packet:
            payload = packet[Raw].load
            payload_size = len(payload)

            # Detect unusually large payloads
            if payload_size > PAYLOAD_THRESHOLD:
                alert_subject = f"ALERT: Unusually large payload from {ip_src}"
                alert_body = f"A payload of {payload_size} bytes was detected from {ip_src} to port {dport}."
                log_alert(alert_subject, alert_body)

            # Detect malicious patterns in the payload
            is_malicious, pattern = detect_malicious_payload(payload)
            if is_malicious:
                alert_subject = f"ALERT: Malicious payload detected from {ip_src}"
                alert_body = f"The pattern '{pattern}' was detected in traffic from {ip_src} to port {dport}."
                log_alert(alert_subject, alert_body)
