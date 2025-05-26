# Python-NIDS-files
My own NIDS created in python (Work in progress)
Currently only checks a pcap for a bruteforce attack, will add more attack detections in the future.
Example bruteforce.pcap is included to make testing easier, any .pcap format file can be used.

Overall function and logic to be used:

•	Since a brute force attack typically originates from a single IP address, targets a single username, and the session must be closed (TCP handshake must be completed),
•	These markers can be used in signature based detection of a brute force attack. If an intercepting proxy with deep packet inspection is setup, the NIDS will also analyze packet payload to generate an alert for any account usernames being targetted
•	I will use a counter system against a specific IP address, if that address is sending multiple login requests to the same username, counter goes up, if the server is responding to an address with multiple login request failed responses/specific HTTP status codes the counter goes up etc...

Key Variables/Markers: 

•	Counter for session #, increments by 1 if ip addr == same, and contains a SYN flag, and a FIN/RST flag (will chunk packets into blocks of SYN and FIN/RST to indicate a session opening and closing)
•	Counter for an ip address, increments by 1 if address is accessing the same uname and, has more than 1 session associated with it, this will keep track of if one address has opened multiple sessions tied to one username (Generalized way of detecting brute force, since not sure if the error message for incorrect password will be the same for multiple servers. This method will 
•	Mark many unique sessions tied to one username as suspicious after a threshold has been reached to account for authorized people simply entering their password wrong since authorized people won't attempt to enter a password 10-20 times, OR, can check the packet timestamps since people won't be entering their password as quickly as a brute force attack tool. can adjust as needed to fit
•	Dictionary variable that stores potentially malicious IP addresses as a key and a counter as the value, the loop will iterate over the pcap file and check every packet that contains an IP layer, and extract the source address from that IP header. the first time a source address is seen, the dictionary will set the value associated with the key (which is the source IP address) to 0, if that address is ever seen again in the pcap file, it will increment that value by 1. This method links a source IP address (key) to a counter (value) which is used to keep track of the amount of times it appeared in a pcap file.
