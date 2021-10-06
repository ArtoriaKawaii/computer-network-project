import socket	# base module
from random import randint
import dns.resolver	# for ip query, first run pip3 install dnspython
import threading    # for each client
import struct   # for data unpacking
from segment import Segment # my TCP packet structure
# 1-1 set arguments
max_rtt = 15/1000	# sec
# in bytes
max_seg_size = 1024
threshold = 64*1024	# ssthresh
buffer_size = 512*1024
tcp_header_len = struct.calcsize('!HHLLBBHHH')

def rand_chksum():
    '''set 25% for better debugging'''
    return int(randint(1,1000000) > 750000)

def handle_request(client_addr:tuple, header:tuple):
    ''' Handle the client '''
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    seq=randint(1,10000)
    ack_seq=header[2]+1
    # Stage 2. send SYN approvement to client
    msg = Segment(tcp_seq=seq, tcp_ack_seq=ack_seq, tcp_chksum=rand_chksum()).raw
    sock.sendto(msg, client_addr)
    print(f'[ SERVER {sock.getsockname()}: SYN ACK to {client_addr} ] with SEQ = {seq}, ACK = {ack_seq}')
    seq+=1
    # Stage 3. receive ack & request from client
    msg, addr = sock.recvfrom(buffer_size)
    header = struct.unpack('!HHLLBBHHH', msg[:tcp_header_len])
    cmdlns = msg[tcp_header_len:].decode('utf-8')
    ack_seq=header[2]+1
    if header[6]:
        # receive REQUEST but packet loss
        print(f'[ SERVER {sock.getsockname()}: REQUEST from {client_addr} ] with packet loss')
    else:
        # receive REQUEST
        print(f'[ SERVER {sock.getsockname()}: REQUEST from {client_addr} ]')
    for cmdln in cmdlns.split('|'):
        cmd = cmdln.split('@')[0]
        ln = cmdln.split('@')[1]
        if cmd == 'video':
            filename='../'+ln
            file=open(filename,'rb')
            delay_ack_counter=0
            while True:	# send until the whole file
                data=file.read(max_seg_size)
                msg = Segment(data=data, tcp_seq=seq, tcp_ack_seq=ack_seq, tcp_chksum=rand_chksum()).raw
                sock.sendto(msg, client_addr)
                print(f'[ SERVER {sock.getsockname()}: RESPONSE video request to {client_addr} with SEQ = {seq}, ACK = {ack_seq} ]')
                seq+=1
                delay_ack_counter+=1
                if delay_ack_counter==3 or data == b'':
                    # wait ack
                    ack_msg, client_addr = sock.recvfrom(buffer_size)
                    header = struct.unpack('!HHLLBBHHH', ack_msg[:tcp_header_len])
                    ack_seq=header[2]+1
                    if (header[5] / 2**4) % 2 and header[6]:
                        # receive ACK but packet loss
                        print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} with packet loss ]')
                    elif (header[5] / 2**4) % 2:
                        # receive ACK
                        print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} ]')
                    else:
                        print(f'SHOULD NOT HAPPEN')
                    delay_ack_counter=0
                if data == b'':
                    break
            file.close()
            print(f'[ SERVER {sock.getsockname()}: REQUEST of video from {client_addr} done ]')
        elif cmd == 'math':
            try:
                ans=eval(ln)
            except:
                print('Error format of math formula')
                ans=-1
            msg = Segment(data=str(ans).encode('utf-8'), tcp_seq=seq, tcp_ack_seq=ack_seq, tcp_chksum=rand_chksum()).raw
            sock.sendto(msg, client_addr)
            print(f'[ SERVER {sock.getsockname()}: RESPONSE math request to {client_addr} ] with SEQ = {seq}, ACK = {ack_seq}')
            seq+=1
            print(f'[ SERVER {sock.getsockname()}: REQUEST of math from {client_addr} done ]')
            # wait ack
            ack_msg, client_addr = sock.recvfrom(buffer_size)
            header = struct.unpack('!HHLLBBHHH', ack_msg[:tcp_header_len])
            ack_seq=header[2]+1
            if (header[5] / 2**4) % 2 and header[6]:
                # receive ACK but packet loss
                print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} with packet loss ]')
            elif (header[5] / 2**4) % 2:
                # receive ACK
                print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} ]')
            else:
                print(f'SHOULD NOT HAPPEN')
        elif cmd == 'dns':
            resolver=dns.resolver.Resolver()
            resolver.nameservers=['8.8.8.8']
            msg = Segment(data=resolver.resolve(ln,'A')[0].to_text().encode('utf-8'), tcp_seq=seq, tcp_ack_seq= ack_seq, tcp_chksum=rand_chksum()).raw
            sock.sendto(msg, client_addr)
            print(f'[ SERVER {sock.getsockname()}: RESPONSE dns request to {client_addr} ] with SEQ = {seq}, ACK = {ack_seq}')
            seq+=1
            print(f'[ SERVER {sock.getsockname()}: REQUEST of dns from {client_addr} done ]')
            # wait ack
            ack_msg, client_addr = sock.recvfrom(buffer_size)
            header = struct.unpack('!HHLLBBHHH', ack_msg[:tcp_header_len])
            ack_seq=header[2]+1
            if (header[5] / 2**4) % 2 and header[6]:
                # receive ACK but packet loss
                print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} with packet loss ]')
            elif (header[5] / 2**4) % 2:
                # receive ACK
                print(f'[ SERVER {sock.getsockname()}: ACK from {client_addr} ]')
            else:
                print(f'SHOULD NOT HAPPEN')
        else:
            pass

# Wait for a client
try:
    # socket.socket() will create a TCP socket (default)
    # socket.socket(socket.AF_INET, socket.SOCK_STREAM) to explicitly define a TCP socket
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)  # explicitly define a UDP socket
    udp_host = socket.gethostbyname(socket.gethostname()) # host IP
    udp_port = 12345    # specified port to connect (main port)
    sock.bind((udp_host,udp_port))
    while True: # keep alive
        try: # receive request from client
            print(f"[ Main Thread {sock.getsockname()} ] Waitting for clients' command...")
            # Stage 1. receive connection request from client
            msg, client_addr = sock.recvfrom(buffer_size)
            header = struct.unpack('!HHLLBBHHH', msg[:tcp_header_len])
            if header[6]:
                # receive SYN REQUEST but packet loss
                print(f'[ Main Thread {sock.getsockname()}: SYN REQUEST from {client_addr} with packet loss ]')
            else:
                # receive SYN REQUEST
                print(f'[ Main Thread {sock.getsockname()}: SYN REQUEST from {client_addr} ]')
            # open new thread to serve a client
            server_thread = threading.Thread(target = handle_request, args = (client_addr, header))
            server_thread.daemon = True
            server_thread.start()
        except OSError as err:
            print(err)
except KeyboardInterrupt:
    ''' Shutdown the UDP server '''
    print()
    print('Shutting down server...')
    sock.close()



