import ipaddress
import sys

# class ICMPPing:
    # Create ICMP socket and set timeout
    # def __init__(self, timeout):

    # Calculate ICMP checksum
    # def checksum(self, data):

    # Send ICMP Echo Request to target
    # def send_request(self, target_addr):

    # Receive ICMP Echo Reply from target
    # def receive_reply(self, target_addr):

    # Ping host specified by address
    # def ping_host(self, target_addr):

class NetworkScanner:
    # Scan a single host and output address if host is active
    def scan_host(self, target_addr):
        print(target_addr)

    # Scan each host in network range
    def scan_network(self, network_addr):
        # TODO check network address is in the correct format
        
        addr_count = 2 ** (32 - int(network_addr.split('/')[1]))
        print('Scanning %d hosts on %s...' % (addr_count, network_addr))

        network = ipaddress.ip_network(network_addr, strict=False)
        for addr in network.hosts():
            self.scan_host(addr)

network_addr = sys.argv[1]
scanner = NetworkScanner()
scanner.scan_network(network_addr)