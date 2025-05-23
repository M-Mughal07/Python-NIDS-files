# rdpcap will read a .pcap file and return contents as a list like object (packetlist). 
# ip allows access to fields within the ipv4 layer of a packet (allows extracting source/destination ip)
from scapy.all import rdpcap, IP, TCP
from datetime import datetime, timedelta
import os

# Dictionary variable that will store source IP addresses as the key, and an int as the value representing a malicious weight,
# the value will increment by 1 if a function determines an address to be potentially malicious.
malicious = {}

# Variable that will mark the login server as the attack target (Used to filter it out of potential attacker addresses)
login_server = set()

# Load pcap file into memory
nids_dir = os.path.dirname(os.path.abspath(__file__))
pcap_path = os.path.join(nids_dir, "bruteforce.pcap")
pcap = rdpcap(pcap_path)
def source_addresses():
    source_count = {}
    # Filters packet info to OSI layer 3 only
    for pkt in pcap:
        if IP in pkt:
            # pkt[IP] returns the IP header of a packet, which is then filtered to return the source address only from that header
            src = pkt[IP].src
            # Put source addresses into a dictionary and track how many times they appear
            source_count[src] = source_count.get(src, 0) + 1
    # When a source address appears >= 100 times in the IP header, generate an alert since that many packets is abnormal for a login session
    for src, pkt_counter in source_count.items():
        if pkt_counter >= 100:
            # Incrementing the malicous weight (value) of a source address to mark it as potentially malicious 
            malicious[src] = malicious.get(src, 0) + 1
            # Check value of source address and generate alert if threshold reached
            if malicious.get(src) >= 1:
                print (f"more than 100 packets detected from source address {src}")
    return source_count

# Function to calculate how quickly a client sends packets to a login server
def packet_timestamp_frequency():
    pkt_counter = 0
    # Will check the frequency between blocks of this many packets
    chunk_size = 50
    # Will store every client packet timestamp
    avg_time = []
    for pkt in pcap:
        client_ip = pkt[IP].src
        # Checks if source address is in malicious dictionary, and if it has a malicious weight of >=1, calculates time delta
        if client_ip in malicious and malicious.get(client_ip) >= 1:  
            # Isolates packet printout to only show client(s) by performing a membership test against the login_server set
            if IP in pkt and client_ip not in login_server:
                pkt_counter += 1
                avg_time.append(pkt.time)
                # Calculates how long it took for the client to send (chunk_size) amount of packets and the average time between each packet (interval)
                if pkt_counter ==  chunk_size:
                    # Use negative index to access the last item of a list without knowing the length of the list
                    delta = avg_time[-1] - avg_time[0]
                    # subtract 1 from the chunk size since intervals between packets have to be calculated
                    avg_interval = delta / (chunk_size - 1)
                    # Assuming HTTPS is being used to login to a web server, the threshold for abnormal packet intervals should be < 5-7 ms
                    if avg_interval < 0.6000:
                        # Generating alert and rounding the value of avg_interval up to 4 digits 
                        print (f"{chunk_size} packets detected with abnormal intervals from {client_ip} at {avg_interval:.4f} seconds between packets")
                    # Resetting the list and counter variables for the next chunk of packets
                    avg_time = []
                    pkt_counter = 0
    # Incrementing malicious counter for client address to mark it as potentially malicious
    malicious[client_ip] = malicious.get(client_ip, 0) + 1
    print (f"DEBUG: {malicious}")


# Same process as source_addresses() function, except filtering the IP header to show destination address only
def destination_addresses():
    dest_count = {}
    for pkt in pcap:
        if IP in pkt:
            dst = pkt[IP].dst
            dest_count[dst] = dest_count.get(dst, 0) + 1
    return dest_count

# Function to check if a packet contains a TCP/SYN flag,
def tcp_syn():
    pkt_count = 0
    for pkt in pcap:
        if TCP in pkt:
            tcp_flags = pkt[TCP].flags
            if tcp_flags == "S":
                # Will print out every TCP/SYN packet sent from the client, effectivly, prints out how many TCP sessions the client initiated with the server
                src_ip_flags = pkt[IP].src
                pkt_count += 1
    # Checking if the source ip from the packets containing TCP/SYN flags is in the malicious IP dictionary
    if src_ip_flags in malicious:
        print(f"Abnormal amount ({pkt_count}) TCP/SYN packets detected from {src_ip_flags}")
        malicious[src_ip_flags] = malicious.get(src_ip_flags, 0) + 1
        print (f"DEBUG: {malicious}")
    # Login server is marked here since only a client will send a TCP/SYN packet
    login_server.add(pkt[IP].dst)
                
# Function that prints an IP address, how many packets it sent/received, and how many times it appeared in the pcap file
def ip_enumerator():
    src_ips = source_addresses()
    dst_ips = destination_addresses()
    all_ips = set(src_ips) | set(dst_ips)
    for ip in sorted(all_ips):
        src_count = src_ips.get(ip, 0)
        dst_count = dst_ips.get(ip, 0)
        total = src_count + dst_count
        print(f"IP Address: {ip}")
        print(f"  → Source count: {src_count}")
        print(f"  → Destination count: {dst_count}")
        print(f"  → Total appearances: {total}\n")



ip_enumerator()
tcp_syn()
packet_timestamp_frequency()