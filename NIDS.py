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
            ''' Takes source address from a packet, then adds it to a dictionary variable, the loop will go down the list of packets in the pcap,
              and check every packet that contains an IP layer, and extract the source address from that IP header. the first time a source address is
              seen, the dictionary will set the value associated with the key (which is the source IP address) to 0, if that address
              is ever seen again in the pcap file, it will increment that value by 1. This method links a source IP address (key) to a counter (value)
              which is used to keep track of the amount of times it appeared in a pcap file.
            '''
            # Put src into dictionary as key then, get key value, if no value, value = 0, then add 1 to value and assign updated value to key.
            source_count[src] = source_count.get(src, 0) + 1
    # When a source address (key) hits a packet count(value) of greater than or equal to 100, it will print that source address
    for src, pkt_counter in source_count.items():
        if pkt_counter >= 100:
            # Incrementing the malicous weight (value) of a source address to mark it as potentially malicious 
            malicious[src] = malicious.get(src, 0) + 1
            if malicious.get(src) >= 1:
                print (f"more than 100 packets detected from source address {src}")
    return source_count


def packet_timestamp_frequency():
    pkt_counter = 0
    previous = None
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
                # Calculates how long it took for the client to send X (chunk_size) amount of packets and the average time between each packet (interval)
                if pkt_counter ==  chunk_size:
                    # Use negative index to access the last item of a list without knowing the length of the list
                    delta = avg_time[-1] - avg_time[0]
                    avg_interval = delta / (chunk_size - 1)
                    print (avg_interval)
                    # Resetting the list and counter variables for the next chunk of packets
                    avg_time = []
                    pkt_counter = 0

                




# Same process as source_addresses() function, except filtering the IP header to show destination address only
def destination_addresses():
    dest_count = {}
    for pkt in pcap:
        if IP in pkt:
            dst = pkt[IP].dst
            dest_count[dst] = dest_count.get(dst, 0) + 1
    return dest_count

# Function to check if a packet contains a TCP SYN flag, this will mark the source IP as the client, and the destination IP as the server, it will also mark the start of the TCP handshake/session
def tcp_syn():
    pkt_count = 0
    for pkt in pcap:
        if TCP in pkt:
            tcp_flags = pkt[TCP].flags
            if tcp_flags == "S":
                # Will print out every SYN packet sent from the client, effectivly, prints out how many TCP sessions the client initiated with the server
                src_ip_flags = pkt[IP].src
                flags = pkt[TCP].flags
                pkt_count += 1
    # Checking if the source ip from the packets containing TCP/SYN flags is in the potentially malicious IP dictionary
    # If there is a match, generate alert stating abnormality 
    if src_ip_flags in malicious:
        print(f"Abnormal amount ({pkt_count}) TCP/SYN packets detected from {src_ip_flags}")
                #print(f"Source: {src_flags}, Destination: {dst_flags}, TCP Flags: {flags}")
    # Login server and client variables are assigned here because only a client will send a TCP/SYN packet,
    # making the destination address of that packet the login server
    login_server.add(pkt[IP].dst)
                

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
print ("DEBUG FOR MALICIOUS DICTIONARY: REMOVE IN FINAL VERSION", malicious)
tcp_syn()
packet_timestamp_frequency()