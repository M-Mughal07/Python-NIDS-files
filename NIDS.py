'''Since a brute force attack typically originates from a single IP address, targets a single username, and the session must be closed (TCP handshake must be completed),
    these markers can be used in signature based detection of a brute force attack. Also, since a NIDS must be placed between a server and client, it will be able to decrypt HTTPS communication/any other encrypted data'''
'''I will use a counter system against a specific IP address, if that address is sending multiple login requests to the same username, counter goes up, if the server is responding to an address with multiple 
    "login request failed responses/specific HTTP status codes the counter goes up etc...
    Attacker must close connection to enter new password'''

''' counter for session #, increments by 1 if ip addr == same, and contains a SYN flag, and a FIN/RST flag (will chunk packets into blocks of SYN and FIN/RST to indicate a session opening and closing)
    counter for an ip address, increments by 1 if address is accessing the same uname and, has more than 1 session associated with it, this will keep track of if one address has opened multiple sessions
      tied to one username (Generalized way of detecting brute force, since not sure if the error message for incorrect password will be the same for multiple servers. This method will 
       mark many unique sessions tied to one username as suspicious after a threshold has been reached to account for authorized people simply entering their password wrong since authorized people
        won't attempt to enter a password 10-20 times, OR, can check the packet timestamps since people won't be entering their password as quickly as a brute force attack tool. can adjust as needed to fit
        syntax for different servers)  '''
# rdpcap will read a .pcap file and return contents as a list like object (packetlist). 
# ip allows access to fields within the ipv4 layer of a packet (allows extracting source/destination ip)
from scapy.all import rdpcap, IP, TCP
import os

# Dictionary variable that will store source IP addresses as the key, and an int as the value, 
# the value will increment by 1 if a function determines an address to be potentially malicious.
malicious = {}

# Load pcap file into memory
nids_dir = os.path.dirname(os.path.abspath(__file__))
pcap_path = os.path.join(nids_dir, "bruteforce.pcap")
pcap = rdpcap(pcap_path)
def source_addresses():
    # Create variable that will store source addresses into a dictionary, which by nature will only store unique items,
    # this acts as a filter to show only unique clients and servers
    source_count = {}
    # For loop that checks if an IP address is present in the packet, this will filter out any communication that takes place on OSI layers 1 and 2 (Does not contain layer 3 communication)
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
    # This loop will check each keys value in the source_count dictionary, 
    # when a source address (key) hits a packet count(value) of greater than or equal to 50, it will print that source address
    for src, counter in source_count.items():
        if counter >= 100:
            # Adding source addresses to the malicious dictionary,
            # Incrementing the value of a source address to mark it as potentially malicious 
            malicious[src] = malicious.get(src, 0) + 1
            if malicious.get(src) >= 1:
                print (f"more than 100 packets detected from source address {src}")
    return source_count


# Same process as source_addresses() function, except filtering the IP header to show destination addresse only
def destination_addresses():
    dest_count = {}
    for pkt in pcap:
        if IP in pkt:
            dst = pkt[IP].dst
            dest_count[dst] = dest_count.get(dst, 0) + 1
    return dest_count

# Function to check if a packet contains a TCP SYN flag, this will mark the source IP as the client, and the destination IP as the server, it will also mark the start of the TCP handshake/session
def tcp_syn():
    for pkt in pcap:
        if TCP in pkt:
            tcp_flags = pkt[TCP].flags
            if tcp_flags == "S":
                # Will print out every SYN packet sent from the client, effectivly, prints out how many TCP sessions the client initiated with the server
                src_flags = pkt[IP].src
                dst_flags = pkt[IP].dst
                flags = pkt[TCP].flags
                if src_flags == malicious.get():
                    print (malicious())
                #print(f"Source: {src}, Destination: {dst}, TCP Flags: {flags}")
                

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





tcp_syn()
ip_enumerator()