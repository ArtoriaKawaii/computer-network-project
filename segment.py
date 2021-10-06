import socket
import struct   # to pack up the packet to bytes

class Segment:
    def __init__(self, dst='127.0.0.1', src='127.0.0.1',
                 tcp_src = 65535, tcp_dst = 80,
                 tcp_seq = 0, tcp_ack_seq = 0, 
                 tcp_flags_cwr = 0, tcp_flags_ece = 0,
                 tcp_flags_urg = 0, tcp_flags_ack = 0,
                 tcp_flags_psh = 0, tcp_flags_rst = 0,
                 tcp_flags_syn = 0, tcp_flags_fin = 0, 
                 tcp_chksum = 0, data = b''):
        self.src_ip = src
        self.dst_ip = dst
        self.data   = data
        # TCP Flags
        self.tcp_src = tcp_src   # Source Port 
        self.tcp_dst = tcp_dst   # Destination Port 
        self.tcp_seq = tcp_seq    # TCP Sequence Number
        self.tcp_ack_seq = tcp_ack_seq    # TCP Acknowledgement Number
        self.tcp_hdr_len = struct.calcsize('!HHLLBBHHH')   # Header Length, const
        self.tcp_flags = (tcp_flags_cwr << 7) + (tcp_flags_ece << 6) \
                       + (tcp_flags_urg << 5) + (tcp_flags_ack << 4) \
                       + (tcp_flags_psh << 3) + (tcp_flags_rst << 2) \
                       + (tcp_flags_syn << 1) + tcp_flags_fin
        self.tcp_chksum = tcp_chksum
        self.tcp_wdw = socket.htons(5840)   # TCP Window Size
        self.tcp_urg_ptr = 0    # TCP Urgent Pointer
        
        # assemble to byte seq
        self.raw = struct.pack('!HHLLBBHHH', # Data Structure Representation
            self.tcp_src,   # Source IP
            self.tcp_dst,    # Destination IP
            self.tcp_seq,    # Sequence
            self.tcp_ack_seq,  # Acknownlegment Sequence
            self.tcp_hdr_len,   # Header Length
            self.tcp_flags,    # TCP Flags
            self.tcp_chksum,    # Check sum to determine wether the packet is lost (0 is normal, 1 is lost)
            self.tcp_wdw,   # TCP Windows
            self.tcp_urg_ptr # TCP Urgent Pointer
            )
        self.raw += data
