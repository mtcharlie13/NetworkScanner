import ipaddress
import os
import queue
import socket
import struct
import sys
import threading
import time
import traceback

# calculate checksum
def get_checksum(data):
    if len(data) % 2:
        data += b'\x00'# make data length even

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]# combine data into 16-bit word
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # invert bits and return 16 bits
    return ~checksum & 0xffff

def check_privileges():
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        icmp_socket.close()
    except socket.error as e:
        print('Error: script requires administator privileges')
        sys.exit()# cannot access sockets without admin privileges on Windows


class ICMPPing:
    def __init__(self):
        self.packet_id = os.getpid() & 0xffff
        self.timeout = 2
        self.sequence_num = 0
        self.packet = self.create_packet()

    # create ICMP packet
    def create_packet(self):
        header = struct.pack('!BBHHH', 8, 0, 0, self.packet_id, self.sequence_num)

        extra_data_len = 56# length needed to reach 64 bytes
        extra_data = str.encode(extra_data_len * 'A')

        checksum = get_checksum(header + extra_data)

        # reconstruct packet with checksum
        header = struct.pack('!BBHHH', 8, 0, checksum, self.packet_id, self.sequence_num)

        return header + extra_data

    # set up socket and ping host specified by address
    def ping_host(self, target_addr):
        if (type(target_addr) == str):# target can also be identified by hostname
            try:
                dst_addr = socket.gethostbyname(target_addr)
            except socket.gaierror as e:
                print('Error: cannot resolve hostname %s' % (target_addr))
                return
        else:
            dst_addr = str(target_addr)# address currently in IPv4 format

        # create ICMP socket and set timeout
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        icmp_socket.settimeout(self.timeout)

        # send ICMP Echo Request to target
        try:
            icmp_socket.sendto(self.packet, (dst_addr, 0))
            time_sent = time.time()
        except socket.error as e:
            traceback.print_exception(e)
            icmp_socket.close()
            return

        # receive ICMP Echo Reply from target and record rtt
        reply_packet = None

        try:
            reply_packet, src_addr = icmp_socket.recvfrom(1024)# read up to 1024 bytes from socket
            time_received = time.time()
            rtt = time_received - time_sent
        except socket.timeout:
            return
        except socket.error as e:
            traceback.print_exception(e)
            return
        finally:
            icmp_socket.close()

        src_addr = src_addr[0]# source address from Reply is currently stored in a tuple
        if src_addr != dst_addr:
            return# addresses do not match
            
        # parse Echo Reply
        ip_header = reply_packet[:20]# first 20 bytes of Reply is the IP header
        version_and_ihl, tos, packet_len, identification, flags_and_offset, ttl, protocol, checksum, src_ip, dst_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        ip_header_len = (version_and_ihl & 0x0f) * 4# bit masking to extract IP header length

        icmp_header = reply_packet[ip_header_len:ip_header_len + 8]
        icmp_type, code, checksum, packet_id, sequence_num = struct.unpack('!BBHHH', icmp_header)

        if self.packet_id != packet_id or self.sequence_num != sequence_num:
            return# ID and sequence numbers do not match between Request and Reply

        return True# Echo Reply was received from target and parsed successfully


class NetworkScanner:
    def __init__(self, max_threads):
        self.max_threads = max_threads
        self.active_hosts = []
        self.lock = threading.Lock()
        self.host_queue = queue.Queue()

    def worker(self):
        while not self.host_queue.empty():
            addr = self.host_queue.get(timeout=2)
            ping = ICMPPing()

            if ping.ping_host(addr):
                print('Found active host: %s' % (addr))
                with self.lock:
                    self.active_hosts.append(addr)

            self.host_queue.task_done()

    # scan each host in network range
    def scan_network(self, network_addr):
        responses = 0

        try:
            addr_count = 2 ** (32 - int(network_addr.split('/')[1]))
            print('Scanning %d hosts on %s...' % (addr_count, network_addr))
            network = ipaddress.ip_network(network_addr, strict=False)
        except ValueError as e:
            print('Error: input must be in CIDR notation')
            return
        
        # queue hosts in network range
        for addr in network.hosts():
            self.host_queue.put(addr)
        
        # start threading
        threads = []
        for i in range(min(self.max_threads, self.host_queue.qsize())):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True# exits when main thread exits
            thread.start()
            threads.append(thread)

        # wait for hosts to be processed
        self.host_queue.join()

        # wait for threads to finish
        for thread in threads:
            thread.join()

        responses = len(self.active_hosts)
        
        if responses == 1:
            print('Scan complete: 1 active host found on %s' % (network_addr))
        else:
            print('Scan complete: %d active hosts found on %s' % (responses, network_addr))

network_addr = sys.argv[1]
scanner = NetworkScanner(50)
check_privileges()
scanner.scan_network(network_addr)