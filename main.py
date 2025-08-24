from scapy.all import sniff
from src.anomaly_detector import analyze_packet, packet_count_per_ip
from src.config import MONITORING_INTERVAL

def main():
    """Main function that monitors the network and detects anomalies.

    This function starts the local network monitoring process by using Scapy's sniff
    function to capture packets. The analyze_packet function is used as the callback
    function for sniff, which is called with each captured packet. The sniff function
    is run for the specified MONITORING_INTERVAL seconds.

    Once the sniff function completes, the function prints a summary of the traffic
    captured, including the number of packets sent by each IP address.

    """
    print(f"Starting local network monitoring for {MONITORING_INTERVAL} seconds...")

    # Start packet capture
    sniff(prn=analyze_packet, timeout=MONITORING_INTERVAL, store=False)

    # Display summary of IPs that have sent packets
    print("\nTraffic summary:")
    if not packet_count_per_ip:
        print("No traffic was captured.")
    else:
        # Print the number of packets sent by each IP address
        for ip, count in packet_count_per_ip.items():
            print(f"IP: {ip}, Packets sent: {count}")

    print("Monitoring finished.")

if __name__ == "__main__":
    main()
