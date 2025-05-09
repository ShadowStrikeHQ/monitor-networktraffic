import argparse
import logging
import sys
from scapy.all import sniff, IP, TCP, UDP
from scapy.utils import PcapWriter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables
packet_count = 0
suspicious_connections = {}  # Dictionary to store suspicious connections (IP: count)
PCAP_FILE = "network_traffic.pcap"

def setup_argparse():
    """
    Sets up the argument parser for the script.
    """
    parser = argparse.ArgumentParser(description="Monitor network traffic for unusual patterns.")
    parser.add_argument("-i", "--interface", help="Network interface to monitor (e.g., eth0, wlan0). If not specified, scapy's default interface will be used.")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp port 80', 'host 192.168.1.1').")
    parser.add_argument("-t", "--threshold", type=int, default=1000, help="Threshold for packet count to flag a connection as suspicious (default: 1000).")
    parser.add_argument("-n", "--number", type=int, default=0, help="Number of packets to capture. If 0, capture indefinitely.")
    parser.add_argument("-d", "--destination", help="Monitor traffic to a specific IP address.")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help="Set the logging level.")
    parser.add_argument("--pcap", action="store_true", help="Enable saving captured packets to a pcap file.")
    
    return parser.parse_args()

def process_packet(packet, threshold, destination, pcap_writer):
    """
    Processes each captured packet, checking for suspicious activity.
    """
    global packet_count, suspicious_connections

    packet_count += 1

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if destination and dst_ip != destination:
                return  # Skip if destination IP is specified and doesn't match
                
            key = (src_ip, dst_ip)
            if key in suspicious_connections:
                suspicious_connections[key] += 1
            else:
                suspicious_connections[key] = 1

            if suspicious_connections[key] > threshold:
                logging.warning(f"Possible suspicious connection: {src_ip} -> {dst_ip} (Packet Count: {suspicious_connections[key]})")

            if pcap_writer:
                pcap_writer.write(packet)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def main():
    """
    Main function to start network traffic monitoring.
    """
    args = setup_argparse()
    logging.getLogger().setLevel(args.log_level)

    interface = args.interface
    bpf_filter = args.filter
    threshold = args.threshold
    number = args.number
    destination = args.destination

    if destination:
        try:
            # Input validation for destination IP address (basic check)
            ip_parts = destination.split(".")
            if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                raise ValueError("Invalid destination IP address format.")
        except ValueError as e:
            logging.error(f"Invalid destination IP address: {e}")
            sys.exit(1)

    logging.info(f"Monitoring network traffic on interface: {interface or 'default'}, filter: '{bpf_filter or 'None'}'")

    pcap_writer = None
    if args.pcap:
        try:
            pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
            logging.info(f"Saving captured packets to {PCAP_FILE}")

        except Exception as e:
            logging.error(f"Failed to open pcap file for writing: {e}")
            pcap_writer = None
        
    try:
        sniff(iface=interface, filter=bpf_filter, prn=lambda x: process_packet(x, threshold, destination, pcap_writer), count=number)

    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
    finally:
        logging.info("Stopping network traffic monitoring.")
        if pcap_writer:
            pcap_writer.close()
            logging.info(f"Packets saved to {PCAP_FILE}")
            
    if args.number:
        logging.info(f"Captured {args.number} packets.")
    else:
         logging.info(f"Captured {packet_count} packets.")

if __name__ == "__main__":
    # Usage examples:
    # 1. Monitor all traffic on the default interface: python main.py
    # 2. Monitor traffic on eth0: python main.py -i eth0
    # 3. Monitor traffic to a specific IP: python main.py -d 192.168.1.100
    # 4. Monitor TCP traffic on port 80: python main.py -f "tcp port 80"
    # 5. Monitor and save packets to a pcap file: python main.py --pcap
    # 6. Set logging level to debug: python main.py --log-level DEBUG
    main()