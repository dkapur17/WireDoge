import socket
import struct
import textwrap
import inquirer

class EthernetFrame:
    def __init__(self, raw_data):

        dest_bytes, src_bytes, proto_bytes = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = self.get_mac(dest_bytes)
        self.src_mac = self.get_mac(src_bytes)
        self.proto = socket.htons(proto_bytes)

        if self.proto == 8:
            self.data = IPv4Packet(raw_data[14:])
        else:
            self.data = None
    
    def get_mac(self, bytes_addr) -> str:
        hex_byte_list = list(map(lambda byte: f"{byte:02x}", bytes_addr))
        return ':'.join(hex_byte_list).upper()
    
    def __str__(self) -> str:
        return (f"Ethernet Frame:\n"
                f"\t - Souce MAC Address: {self.src_mac}\n"
                f"\t - Destination MAC Address: {self.dest_mac}\n"
                f"\t - Protocol: {self.proto}\n"
                f"\t - {self.data}\n"
                )


class IPv4Packet:
    def __init__(self, raw_data):

        self.version = raw_data[0] >> 4
        self.header_length = (raw_data[0] & 15) * 4

        self.ttl, self.proto, src_bytes, dest_bytes = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src_ip = self.get_ip(src_bytes)
        self.dest_ip = self.get_ip(dest_bytes)

        if self.proto == 1:
            self.data = ICMPSegment(raw_data[self.header_length:])
        elif self.proto == 6:
            self.data = TCPSegment(raw_data[self.header_length:])
        elif self.proto == 17:
            self.data = UDPSegment(raw_data[self.header_length:])
        else:
            self.data = None

    def get_ip(self, bytes_addr) -> str:
        return '.'.join(map(str, bytes_addr))
    
    def __str__(self) -> str:
        return (f"IPv4 Packet:\n"
                f"\t\t - Version: {self.version}\n"
                f"\t\t - Header Length: {self.header_length}\n"
                f"\t\t - Time to Live: {self.ttl}\n"
                f"\t\t - Source IP Address: {self.src_ip}\n"
                f"\t\t - Destination IP Address: {self.dest_ip}\n"
                f"\t\t - Protocol: {self.proto}\n"
                f"\t\t - {self.data}"
                )


class TransportSegment:
    def __init__(self, data):
        self.data = data
    
    def __str__(self) -> str:
        return f"Other Transport Segment"
    
    def format_data(self, data):
        data_string = ''.join(f'\\x{byte:02x}' for byte in data)

        return '\n\t\t\t\t '.join(line for line in textwrap.wrap(data_string, 100))


class ICMPSegment(TransportSegment):
    def __init__(self, data):
        self.icmp_type, self.code, self.checksum = struct.unpack('! B B H', data[:4])
        self.data = data[4:]
    
    def __str__(self) -> str:
        return (f"ICMP Segment:\n"
                f"\t\t\t - Type: {self.icmp_type}\n"
                f"\t\t\t - Code: {self.code}\n"
                f"\t\t\t - Checksum: {self.checksum}\n"
                f"\t\t\t - Data: {self.format_data(self.data)}"
                )

class TCPSegment(TransportSegment):
    def __init__(self, data):
        self.src_port, self.dest_port, self.sequence, self.acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = data[self.offset:]
    
    def __str__(self) -> str:
        return (f"TCP Segment:\n"
                f"\t\t\t - Source Port: {self.src_port}\n"
                f"\t\t\t - Destination Port: {self.dest_port}\n"
                f"\t\t\t - Sequence: {self.sequence}\n"
                f"\t\t\t - Acknowledgement: {self.acknowledgement}\n"
                f"\t\t\t - Flags:\n"
                f"\t\t\t\t - URG: {self.flag_urg} | ACK: {self.flag_ack} | PSH: {self.flag_psh} | RST: {self.flag_rst} | SYN: {self.flag_syn} | FIN: {self.flag_fin}\n"
                f"\t\t\t - Data: {self.format_data(self.data) if len(self.data) else 'None'}"
                )

class UDPSegment(TransportSegment):
    def __init__(self, data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', data[:8])
        self.data = data[8:]
    
    def __str__(self) -> str:
        return (f"UDP Segment:\n"
                f"\t\t\t - Source Port: {self.src_port}\n"
                f"\t\t\t - Destination Port: {self.dest_port}\n"
                f"\t\t\t - Size: {self.size}\n"
                f"\t\t\t - Data: {self.format_data(self.data)}"
                )

def sniff(target_ip, protocols):

    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    protocol_names = [protocol_map[x] for x in protocols]
    protocol_names = ', '.join(protocol_names[:-2] + [' and '.join(protocol_names[-2:])]) 

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(f"Doge is now sniffing for {protocol_names} segments packets belonging to {target_ip}")
    frames = []
    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            eth_frame = EthernetFrame(raw_data)

            if eth_frame.proto == 8 and (eth_frame.data.src_ip == target_ip or eth_frame.data.dest_ip == target_ip) and eth_frame.data.proto in protocols:
                print(eth_frame)
                frames.append(eth_frame)
    except KeyboardInterrupt:
        print("Finished Sniffing...")
        dump_choices = [inquirer.List('dump', message="Would you like to save the sniffed frames? ", choices=["No", "Yes"])]
        dump = inquirer.prompt(dump_choices)['dump']
        return frames if dump == 'Yes' else None

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth_frame = EthernetFrame(raw_data)
        if eth_frame.proto == 8 and eth_frame.data.proto in [1,6,17]:
            print(eth_frame)


if __name__=="__main__":
    main()
