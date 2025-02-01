import scapy.all as scapy
import matplotlib.pyplot as plt
from collections import defaultdict
import time
from datetime import datetime

total_data_transferred = 0
packet_sizes = []
src_dst_pairs = set()
src_ip_flows = defaultdict(int)
dst_ip_flows = defaultdict(int)
src_dst_data_transfer = defaultdict(int)
hidden_message_packets = []
start_time = time.time()
packet_count = 0

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    global total_data_transferred, packet_sizes, src_dst_pairs, src_ip_flows, dst_ip_flows, src_dst_data_transfer, hidden_message_packets, packet_count

    packet_count += 1
    total_data_transferred += len(packet)
    packet_sizes.append(len(packet))

    if 'IP' in packet and 'TCP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport

        src_dst_pair = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        src_dst_pairs.add(src_dst_pair)
        src_ip_flows[src_ip] += 1
        dst_ip_flows[dst_ip] += 1
        src_dst_data_transfer[src_dst_pair] += len(packet)

        # Part 2: Hidden Message Detection (Hint based on source port 1579 and keyword "CS331")
        if packet['TCP'].sport == 1579 and 'Raw' in packet and b"CS331" in packet['Raw'].load:
            hidden_message_packets.append(packet)

def write_output(message, output_file):
    """
    Write message to both console and file
    """
    print(message)
    output_file.write(message + '\n')

def analyze_captured_traffic():
    """
    Analyzes the captured traffic and prints metrics and answers.
    """
    global total_data_transferred, packet_sizes, src_dst_pairs, src_ip_flows, dst_ip_flows, src_dst_data_transfer, hidden_message_packets, packet_count, start_time

    # Create output file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"capture_analysis_{timestamp}.txt"
    
    with open(output_filename, 'w') as f:
        end_time = time.time()

        write_output("--- Live Capture Analysis ---", f)

        # Part 1.1: Total Data, Packet Count, Packet Sizes
        num_packets = packet_count
        min_packet_size = min(packet_sizes) if packet_sizes else 0
        max_packet_size = max(packet_sizes) if packet_sizes else 0
        avg_packet_size = sum(packet_sizes) / num_packets if num_packets > 0 else 0

        write_output("\nPart 1.1 Metrics:", f)
        write_output(f"Total Data Transferred: {total_data_transferred} bytes", f)
        write_output(f"Total Packets Transferred: {num_packets}", f)
        write_output(f"Minimum Packet Size: {min_packet_size} bytes", f)
        write_output(f"Maximum Packet Size: {max_packet_size} bytes", f)
        write_output(f"Average Packet Size: {avg_packet_size:.2f} bytes", f)

        # Packet Size Distribution (Histogram)
        plt.figure(figsize=(10, 6))
        plt.hist(packet_sizes, bins=50, edgecolor='black') # Adjust bins as needed
        plt.title('Packet Size Distribution (Live Capture)')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.grid(axis='y', alpha=0.75)
        histogram_filename = f'live_packet_size_histogram_{timestamp}.png'
        plt.savefig(histogram_filename)
        write_output(f"Live packet size histogram saved to {histogram_filename}", f)

        # Part 1.2: Unique Source-Destination Pairs
        write_output("\nPart 1.2: Unique Source-Destination Pairs:", f)
        for pair in src_dst_pairs:
            write_output(pair, f)

        # Part 1.3: IP Flow Dictionaries and Top Data Transfer Pair
        write_output("\nPart 1.3: IP Flow Dictionaries:", f)
        write_output("Source IP Flow Dictionary:", f)
        write_output(str(dict(src_ip_flows)), f)
        write_output("\nDestination IP Flow Dictionary:", f)
        write_output(str(dict(dst_ip_flows)), f)

        top_data_pair = max(src_dst_data_transfer, key=src_dst_data_transfer.get) if src_dst_data_transfer else "No flows"
        write_output(f"\nSource-Destination pair with most data transferred: {top_data_pair} ({src_dst_data_transfer.get(top_data_pair, 0)} bytes)", f)

        # Part 2 Analysis (If hidden_message_packets is not empty)
        if hidden_message_packets:
            write_output("\n--- Part 2: Hidden Message Analysis ---", f)
            # Part 2.1: Extract Hidden Message
            hidden_message_packet = hidden_message_packets[0] # Assuming first packet contains the full message
            hidden_message_raw_layer = hidden_message_packet['Raw'].load
            try:
                hidden_message = hidden_message_raw_layer.decode('utf-8')  # Assuming UTF-8 encoding
            # Extract message after "CS331:" if present, otherwise take the whole payload.
                if "CS331:" in hidden_message:
                    hidden_message = hidden_message.split("CS331:", 1)[1].strip()
            except UnicodeDecodeError:  # If not UTF-8, try ASCII or handle binary data if needed.
                hidden_message = "Could not decode message as text. Raw payload: " + str(hidden_message_raw_layer)

            write_output(f"Part 2.1: Hidden Message: {hidden_message}", f)
            # Part 2.2: Number of Packets with Hidden Message
            write_output(f"Part 2.2: Number of Packets with Hidden Message: {len(hidden_message_packets)}", f)
            # Part 2.3: Protocol
            protocol = hidden_message_packets[0].sprintf("%IP.proto%") # Get IP Protocol number
            protocol_name = "TCP" # Based on hint and common usage for hidden messages in TCP payload.
            write_output(f"Part 2.3: Protocol: {protocol_name} (IP Protocol Number: {protocol})", f)
            # Part 2.4: TCP Checksum
            write_output(f"Part 2.4: TCP Checksum: {hidden_message_packets[0]['TCP'].chksum}", f)
        else:
            write_output("\n--- Part 2: No Hidden Message Found based on criteria (port 1579, keyword CS331) ---", f)

        write_output(f"\nAnalysis results saved to {output_filename}", f)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (e.g., eth0, lo): ")
    print(f"Sniffing on interface: {interface}...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda pkt: False) # Capture until stopped manually or tcpreplay finishes.
    analyze_captured_traffic() # Analyze metrics after sniffing is done (when tcpreplay finishes).
    print("Sniffing and analysis complete.")