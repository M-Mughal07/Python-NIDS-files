# The scapy module is used here to analze and extract packet information from a .pcap file
# The rdpcap class will read a .pcap file and return the contents as a list like object (packetlist). 
# Subsequent classes extract their respective layers of data from a packet (IP layer, Raw packet data layer, TCP layer etc...)
from scapy.all import rdpcap, IP, TCP, Raw
# datetime module used to calculate time intervals between client packets
from datetime import datetime, timedelta
# os module used to locate the .pcap file being analyzed 
import os

# Dictionary variable that will store source IP addresses as the key, and an int as the value representing a malicious weight,
# the value will increment by 1 if a function determines an address to be potentially malicious.
malicious = {}
# Variable that will mark the login server as the attack target (Used to filter it out of potential attacker addresses)
login_server = set()
# Assumes the .pcap file is in the same folder as this NIDS.py file
nids_dir = os.path.dirname(os.path.abspath(__file__))
# Asking user for name of pcap file
#pcap_file = input("Enter the name of the packet capture file you want to analyze:")                                            CHANGE IN FUTURE
pcap_path = os.path.join(nids_dir, "bruteforce.pcap")
# Loading .pcap file into memory 
pcap = rdpcap(pcap_path)

# Function that checks how many times a source address sent a packet in the pcap file, generates an alert if a threshold is reached
def source_addresses():
    source_count = {}
    # Filters packet info to OSI layer 3 only
    for pkt in pcap:
        if IP in pkt:
            # pkt[IP] returns the IP header of a packet, which is then filtered to return the source address only from that header
            src = pkt[IP].src
            dst = pkt[IP].dst
            # Put source addresses into a dictionary and track how many times they appear
            source_count[src] = source_count.get(src, 0) + 1
    # When a source address appears >= 100 times in the IP header, generate an alert since that many packets is abnormal for a login session
    for src, pkt_counter in source_count.items():
        if pkt_counter >= 100:
            # Incrementing the malicous weight (value) of a source address to mark it as potentially malicious 
            malicious[src] = malicious.get(src, 0) + 1
            # Check value of source address and generate alert if threshold reached
            if malicious.get(src) >= 1:
                print (f"more than 100 packets detected from source address {src} to {dst}. \n")
    return source_count


# Function to calculate how quickly a client sends packets to a login server, only active if malicious counter >= 1 for any source address
# Detection is based on intervals between a chunk of packets
def packet_timestamp_frequency():
    pkt_counter = {}
    # Will check the frequency between blocks of this many packets
    chunk_size = 50
    chunk_printout_counter = 0
    # Will store every client packet timestamp
    avg_time = {}
    # dictionary for client address, stores value that marks address as having abnormal intervals between packets
    abnormal_intervals = {}
    for pkt in pcap:
        # Isolates packet printout to only show client(s) by performing a membership test against the login_server set
        if IP in pkt and pkt[IP].src not in login_server:
            client_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            # Adds a client address to the dictionary, then adds a tracker value to that address which represents how many packets the client sent
            pkt_counter[client_ip] = pkt_counter.get(client_ip, 0) + 1
            # Checking if a client_ip exists in avg_time as a key, sets the default value to be an empty list and adds the packet timestamp to that list 
            avg_time.setdefault(client_ip, []).append(pkt.time)
            abnormal_intervals.setdefault(client_ip, False)
            # Calculates how long it took for the client to send (chunk_size) amount of packets and the average time between each packet (interval)
            if pkt_counter.get(client_ip, 0) ==  chunk_size:
                # Calculate the time difference between the first packet and the last packet in a chunk
                # Uses negative indexing to access the last item of a list without knowing the length of the list
                delta = avg_time[client_ip][-1] - avg_time[client_ip][0]
                # subtract 1 from the chunk size since intervals between packets have to be calculated
                avg_interval = delta / (chunk_size - 1)
                # Assuming HTTPS is being used to login to a web server, the threshold for abnormal packet intervals should be < 5-7 ms
                if avg_interval < 0.6000:
                    chunk_printout_counter += 1
                    # Setting dictionary value to True for client address if it reaches the threshold
                    abnormal_intervals[client_ip] = True
                    # Generating alert and rounding the value of avg_interval up to 4 digits
                    print (f"{chunk_printout_counter}: {chunk_size} packets detected with abnormal intervals from {client_ip} to {dst_ip} at {avg_interval:.4f} seconds between packets.")
                    pkt_counter[client_ip] = 0
                    avg_time[client_ip] = []
                # This statement changes the abnormality marker for a client back to false if their packet intervals aren't abnormal anymore
                else:
                    abnormal_intervals[client_ip] = False
    # Checking abnormal_intervals value, if True, increment malicious value against a client address
    for client, is_abnormal in abnormal_intervals.items():
        if is_abnormal:
            # Incrementing malicious counter for client address to mark it as potentially malicious
            malicious[client] = malicious.get(client, 0) + 1
    print (f"DEBUG: {malicious}")


# Simmilar process as source_addresses() function, except filtering the IP header to show destination address only, used in the ip_enumerator()
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
            # Checks if current packet contains a TCP/SYN flag and tracks how many there are, effectivly; tracks how many sessions a client initiated
            if tcp_flags == "S":
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                pkt_count += 1
    # Checking if the source ip from the packets containing TCP/SYN flags is in the malicious IP dictionary
    if src_ip in malicious:
        print(f"Abnormal amount ({pkt_count}) TCP/SYN packets detected from {src_ip} to {dst_ip}. \n")
        malicious[src_ip] = malicious.get(src_ip, 0) + 1
        print (f"DEBUG: {malicious}")
    # Login server is marked here since only a client will send a TCP/SYN packet
    login_server.add(pkt[IP].dst)
                

# Function that will check if an attacker is targetting any specific username
# Extract packet payload, isolate lines to show anything related to username ("username =, user = uname =" etc)
def uname_alerts():
    login_tracker = {}
    for pkt in pcap:
        src_ip = pkt[IP].src
        # Filtering packet information by payload presence, and showing malicious addresses only
        if Raw in pkt and src_ip in malicious and src_ip not in login_server:
            # .decode converts a byte string into a readable string (unicode), .load accesses the data bytes in the Raw layer of a packet
            payload = pkt[Raw].load.decode()
            # Removing trailing whitespaces/lines to clean up output with .strip
            clean_payload = payload.strip()
            # Adding source address to dictionary to track what usernames it attempts to login to
            if src_ip not in login_tracker:
                login_tracker[src_ip] = {}
            # Matching a keyword to packet payload to detect if a client attempts login to any username
            for keyword in ["user", "username", "user name", "uname"]:
                # Assigning new name to clean_payload for clarity 
                uname = clean_payload
                # Setting the payload to all lowercase to allow for easier keyword detection
                if keyword in uname.lower():
                    # Nested dictionaries like a folder tree, uname is a subdirectory inside src_ip;
                    # It contains all usernames a client attempted to login to, and how many times login was attempted 
                    login_tracker[src_ip][uname] = login_tracker[src_ip].get(uname, 0) + 1
    # These loops will extract keys and values from both nested dictionaries and generate an alert when malicious addresses attempt login to any account
    for address, user in login_tracker.items():
        # Extracting key-value pairs from user which contain the username accessed, and how many times login was attempted
        for key, value in user.items():
            # Failed login threshold set to 10 to minimize false positives
            if value >= 10:
                # Increment malicious counter against client address if 10 failed logins detected for one username
                malicious[address] = malicious.get(address, 0) + 1
        print (f"\n Client: {address} attempted to log in to:")
        for target_user, counter in user.items():
            print (f" {target_user} | {counter} time(s)")
    print (f"DEBUG: {malicious}")


def malicious_alert_generator():
    # Generator expression that checks all values in the malicious dictionary, returns True if no values are >= 2, and prints alert
    if not any(counter >= 2 for address, counter in malicious.items()):
        print ("No malicious client addresses detected")
        return
    print ('''
    Threat rating breakdown:
    Rating of 2-3: Client address met 2 to 3 malicious communications checks
    Rating of 4: Client address met every malicious communications check, and is very likely an attacker
    ''')
    # Loop that checks values in the malicious dictionary, generates alerts based on the threshold the value reaches
    for address, counter in malicious.items():
        if address not in login_server and counter >= 4:
            print (f"HIGH ALERT: Malicious client(s) ({address}) detected with a threat rating of {counter}")
        elif address not in login_server and counter >= 2:
            print (f"Potentially malicious client(s) ({address}) detected with a threat rating of {counter}")

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


print ("\nDEBUG: ip_enumerator():\n")
ip_enumerator()
print ("\nDEBUG: tcp_syn():\n")
tcp_syn()
print ("\nDEBUG: packet_timestamp_frequency():\n")
packet_timestamp_frequency()
print ("\nDEBUG: uname_alerts():\n")
uname_alerts()
print ("\n DEBUG: malicious_alert_generator():\n")
malicious_alert_generator()