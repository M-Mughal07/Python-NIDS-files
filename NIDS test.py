'''Since a brute force attack typically originates from a single IP address, targets a single username, and the session must be closed (TCP handshake must be completed),
    these markers can be used in signature based detection of a brute force attack. Also, since a NIDS must be placed between a server and client, it will be able to decrypt HTTPS communication/any other encrypted data'''
'''I will use a counter system against a specific IP address, if that address is sending multiple login requests to the same username, counter goes up, if the server is responding to an address with multiple 
    "login request failed responses/specific HTTP status codes the counter goes up etc...
    Attacker must close connection to enter new password'''


# Absolute path variable since Python wouldn't work with the relative path
path = r"C:\Users\Muhammad\Desktop\NIDS python files\test.txt"
# Counter to increment if a brute force attack is detected in a line/packet
counter = 0
# With statement automatically opens and closes the pcap file so it doesn't sit in memory forever
with open(path, "r") as file:
    # For loop to check for brute force attack in each packet
    for line in file:
        isolated = line.strip()
        if "brute" in isolated:
            counter += 1
# Only prints counter number if it is greater than 0 meaning, only prints if an attack or more than one is present
if counter > 0:
    print("There were", counter, "Bruteforce attack(s) detected")
else:
    print("No Brute force attacks were detected")
    