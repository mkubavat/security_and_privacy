import sys
import ipaddress


def parse_packet(packet):
    lines = packet.split('\n')
    packet_number = int(lines[0].strip())  # First line is the packet number
    hex_data = ''.join(line.split(':')[1].strip().replace(' ', '') for line in lines[1:] if ':' in line)
    
    ip_src = extract_ip(hex_data[24:32])
    ip_dst = extract_ip(hex_data[32:40])
    length = int(hex_data[4:8], 16)
    protocol = int(hex_data[18:20], 16)
    ip_header_length = (int(hex_data[1], 16) & 0x0F) * 4

    icmp_type = None
    icmp_identifier = None
    icmp_seq_number = None
    if protocol == 1:  # ICMP protocol number
        icmp_header_start = ip_header_length * 2  # Convert header length to hex char index
        icmp_type = int(hex_data[icmp_header_start:icmp_header_start + 2], 16)
        icmp_identifier = int(hex_data[icmp_header_start + 4:icmp_header_start + 8], 16)
        icmp_seq_number = int(hex_data[icmp_header_start + 8:icmp_header_start + 12], 16)

    # Extract TCP ports, sequence and acknowledgment numbers, and flags if it's a TCP packet (protocol 6)
    if protocol == 6:  # TCP protocol number is 6
        tcp_header_start = ip_header_length * 2  # Convert header length to hex char index
        src_port = int(hex_data[tcp_header_start:tcp_header_start + 4], 16)
        dst_port = int(hex_data[tcp_header_start + 4:tcp_header_start + 8], 16)
        seq_num = int(hex_data[tcp_header_start + 8:tcp_header_start + 16], 16)  # Sequence Number
        ack_num = int(hex_data[tcp_header_start + 16:tcp_header_start + 24], 16)  # Acknowledgment Number
        flags_offset = tcp_header_start + 26  # Flags are offset 13 bytes (26 hex chars) from start of TCP header
        flags_hex = hex_data[flags_offset:flags_offset + 2]
        flags_bin = bin(int(flags_hex, 16))[2:].zfill(8)  # Convert hex to binary, fill to ensure 8 bits
        syn = int(flags_bin[-2])  # SYN flag is second from right
        ack = int(flags_bin[-5])  # ACK flag is fifth from right
        fin = int(flags_bin[-1])  # FIN flag is the rightmost bit
        rst = int(flags_bin[-3])  # RST flag is third from right
    else:
        src_port = dst_port = seq_num = ack_num = syn = ack = fin = rst = None

    packet_info = {
        'number': packet_number,
        'ip_src': ip_src,
        'ip_dst': ip_dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq_num,
        'ack_num': ack_num,
        'length': length,
        'protocol': protocol,
        'ip_header_length': ip_header_length,
        'icmp_type': icmp_type,
        'icmp_identifier': icmp_identifier,
        'icmp_seq_number': icmp_seq_number,
        'flags': {'SYN': syn, 'ACK': ack, 'FIN': fin, 'RST': rst}
    }

    #print("in parse_packet")
    #print(packet_info)  # Debug output to check parsed data
    #print("out")
    return packet_info

def extract_ip(hex_str):
    """Extract an IP address from hex data."""
    return '.'.join(str(int(hex_str[i:i+2], 16)) for i in range(0, 8, 2))



def check_subnet(ip, subnet):
    """
    Check if the given IP address is within the specified subnet.
    
    Args:
    ip (str): IP address to check.
    subnet (str): Subnet in CIDR notation.
    
    Returns:
    bool: True if IP is within the subnet, False otherwise.
    """
    # Convert both IP and subnet to appropriate network objects and compare
    ip_net = ipaddress.ip_address(ip)
    subnet_net = ipaddress.ip_network(subnet, strict=False)  # Non-strict allows subnets without host bits all zeroed
    return ip_net in subnet_net

def read_packets(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()  # Splits packets on blank lines
    packets = []
    current_packet = []
    for line in lines:
        if line.strip().isdigit():  # Check if the line is just a number
            if current_packet:
                packets.append("\n".join(current_packet))
                current_packet = []
        current_packet.append(line.strip())
    if current_packet:  # Add the last packet if there is any
        packets.append("\n".join(current_packet))
    """print("Total packets read:", len(packets))
    for i, packet in enumerate(packets):
        print(f"Packet {i + 1} content:")
        print(packet)
        print("----------")"""
    return packets #[parse_packet(packet) for packet in packets if packet.strip()]  # Avoids processing empty strings


def filter_ingress(packets):
    results = []
    """
    for packet in packets:
        print(packet)"""
        
    for packet in packets:
        ppacket=parse_packet(packet)
        ip_src = ppacket['ip_src']
        if check_subnet(ip_src, "142.58.23.0/24"):
            results.append((ppacket['number'], "yes"))
        else:
            results.append((ppacket['number'], "no"))

    return results

def filter_attacks(packets):
    results = []
    broadcast_address = "142.58.23.0/24"
    ping_of_death_threshold = 65535
    icmp_identifier_threshold = 60000 
    icmp_seq_number_threshold = 600  

    for packet in packets:
        ppacket = parse_packet(packet)
        #print(f"Packet {ppacket['number']}: Type={ppacket.get('icmp_type')}, Length={ppacket['length']}, Destination={ppacket['ip_dst']}, Identifier={ppacket.get('icmp_identifier')}, Sequence Number={ppacket.get('icmp_seq_number')}")

        if ppacket['protocol'] == 1:  # ICMP protocol
            if ppacket.get('icmp_type') == 8:  # Checking if it's an ICMP echo request
                if ppacket['ip_dst'] == broadcast_address:
                    results.append((ppacket['number'], "yes"))
                    #print(f"Packet {ppacket['number']} flagged as smurf attack.")
                elif ppacket['length'] > ping_of_death_threshold:
                    results.append((ppacket['number'], "yes"))
                    #print(f"Packet {ppacket['number']} flagged as ping of death.")
                elif ppacket['icmp_identifier'] > icmp_identifier_threshold or ppacket['icmp_seq_number'] > icmp_seq_number_threshold:
                    results.append((ppacket['number'], "yes"))
                    #print(f"Packet {ppacket['number']} flagged as ping of death due to large ICMP identifier or sequence number.")
                else:
                    results.append((ppacket['number'], "no"))
            else:
                results.append((ppacket['number'], "no"))
        else:
            results.append((ppacket['number'], "no"))

    return results

"""
def track_connections(packets):
    results = []
    connections = {}  # Dictionary to track the state of each connection

    for packet in packets:
        ppacket = parse_packet(packet)

        # Connection identifier
        conn_key = (ppacket['ip_src'], ppacket['ip_dst'], ppacket['src_port'], ppacket['dst_port'])

        # Default to CLOSED if no connection exists
        if conn_key not in connections:
            connections[conn_key] = {'state': 'CLOSED', 'seq': None, 'ack': None}

        # Current packet info
        flags = ppacket['flags']
        seq_num = ppacket['seq_num']
        ack_num = ppacket['ack_num']
        state = connections[conn_key]['state']

        # State machine logic for TCP 3-way handshake
        if flags['SYN'] and not flags['ACK'] and state == 'CLOSED':
            # SYN packet initializing connection
            connections[conn_key] = {'state': 'SYN_SENT', 'seq': seq_num, 'ack': None}
            results.append((ppacket['number'], "yes"))
        elif flags['SYN'] and flags['ACK'] and state == 'SYN_SENT':
            # SYN-ACK packet in response to SYN
            connections[conn_key] = {'state': 'SYN_RECEIVED', 'seq': seq_num, 'ack': ack_num}
            results.append((ppacket['number'], "yes"))
        elif not flags['SYN'] and flags['ACK'] and state == 'SYN_RECEIVED' and ack_num == connections[conn_key]['seq'] + 1:
            # ACK packet finalizing the 3-way handshake
            connections[conn_key] = {'state': 'ESTABLISHED'}
            results.append((ppacket['number'], "yes"))
        else:
            results.append((ppacket['number'], "no"))

    return results
"""
def track_connections(packets):
    results = []
    connections = {}  # Dictionary to track the state and details of each connection

    for packet in packets:
        ppacket = parse_packet(packet)
        
        # Process only TCP packets, others are "no"
        if ppacket['protocol'] != 6:
            results.append((ppacket['number'], "no"))
            continue

        # Define connection key and its reverse for bidirectional handling
        conn_key = (ppacket['ip_src'], ppacket['ip_dst'], ppacket['src_port'], ppacket['dst_port'])
        reverse_key = (ppacket['ip_dst'], ppacket['ip_src'], ppacket['dst_port'], ppacket['src_port'])

        # Determine the active key for the connection
        active_key = conn_key if conn_key in connections else reverse_key if reverse_key in connections else conn_key
        connections.setdefault(active_key, {'state': 'CLOSED', 'established': False})

        # Extract state info
        state_info = connections[active_key]
        state = state_info['state']
        established = state_info['established']
        flags = ppacket['flags']

        # State transitions based on flags
        if flags['SYN'] and not flags['ACK']:
            state = 'SYN_SENT'
        elif flags['SYN'] and flags['ACK'] and state == 'SYN_SENT':
            state = 'SYN_RECEIVED'
        elif flags['ACK'] and state == 'SYN_RECEIVED':
            state = 'ESTABLISHED'
            established = True

        # Update connection info
        connections[active_key] = {'state': state, 'established': established}

        # Decide on packet validity
        if flags['FIN'] or flags['RST']:
            results.append((ppacket['number'], "yes")) if established else results.append((ppacket['number'], "no"))
        else:
            results.append((ppacket['number'], "no"))

    return results


def main():
    option = sys.argv[1]
    filename = sys.argv[2]
    packets = read_packets(filename)  # Implement reading and parsing logic
    """for packet in packets:
        print(packet) """

    if option == '-i':
        results = filter_ingress(packets)
    elif option == '-j':
        results = filter_attacks(packets)
    elif option == '-k':
        results = track_connections(packets)

    for result in results:
        print(f"{result[0]} {result[1]}")

if __name__ == "__main__":
    main()
