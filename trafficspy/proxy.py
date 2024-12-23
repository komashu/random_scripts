import sys
import socket
import threading
import time
import dpkt


# TODO figure out why the packets aren't fully captured correctly. 
# TODO figure out how to follow everything from link to link.


def server_loop(lhost, lport, rhost, rport, first=False):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((lhost, int(lport)))
    except Exception as e:
        print(f"Failed to listen on {lhost}:{lport}")
        print("Error: Did you run with sudo or are sockets already in use?")
        print(f"Error details: {e}")
        sys.exit(0)

    print(f"Listening on {lhost}:{lport}")
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        print(f"==> Incoming connection from {addr[0]}:{addr[1]}")
        proxy_thread = threading.Thread(
            target=proxy_handler, args=(client_socket, rhost, rport, first))
        proxy_thread.start()


def proxy_handler(client_socket, rhost, rport, first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rhost_ip = socket.gethostbyname(rhost)
    pcap_file = f"{rhost}_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
    remote_socket.connect((rhost, int(rport)))
    proxy_ip, proxy_port = client_socket.getsockname()

    with open(pcap_file, "wb") as f:
        pcap_writer = dpkt.pcap.Writer(f)
        print(f"Logging traffic to {pcap_file}")

        if first:
            remote_buffer = receive_from(remote_socket)
            hexdump(remote_buffer)
            log_to_pcap_dpkt(
                        pcap_writer,
                        remote_buffer,
                        src_ip=rhost_ip,
                        dst_ip=proxy_ip,
                        src_port=int(rport),
                        dst_port=int(proxy_port),
                    )
    
            remote_buffer = response_handler(remote_buffer)
            if remote_buffer:
                print(f"<== Sending {len(remote_buffer)} bytes to localhost.")
                client_socket.send(remote_buffer)
    
        while True:
            local_buffer = receive_from(client_socket)
            if local_buffer:
                print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
                hexdump(local_buffer)
                log_to_pcap_dpkt(
                        pcap_writer,
                        local_buffer,
                        src_ip=proxy_ip,
                        dst_ip=rhost_ip,
                        src_port=int(proxy_port),
                        dst_port=int(rport),
                    )
                local_buffer = request_handler(local_buffer, rhost)
                remote_socket.send(local_buffer)
                print("[==>] Sent to remote.")
    
            remote_buffer = receive_from(remote_socket)
            if remote_buffer:
                print(f"Received {len(remote_buffer)} bytes from remote {rhost}.")
                hexdump(remote_buffer)
                log_to_pcap_dpkt(
                        pcap_writer,
                        remote_buffer,
                        src_ip=rhost_ip,
                        dst_ip=proxy_ip,
                        src_port=int(rport),
                        dst_port=int(proxy_port),
                    )
                pcap_writer.writepkt(remote_buffer) 
                remote_buffer = response_handler(remote_buffer)
                client_socket.send(remote_buffer)
                print("[<==] Sent to localhost.")
    
            if not local_buffer and not remote_buffer:
                client_socket.close()
                remote_socket.close()
                pcap_writer.close()
                print(f"No more data. Ending connection. Traffic logged to {pcap_file}")
                break


def hexdump(src, length=16):
    if not isinstance(src, (bytes, str)):
        raise ValueError("Input must be of type 'bytes' or 'str'.")
    result = []
    is_unicode = isinstance(src, str)

    for i in range(0, len(src), length):
        s = src[i:i + length]
        hexa = ' '.join([f"{ord(x):02X}" if is_unicode else f"{x:02X}" for x in s])
        text = ''.join([x if 0x20 <= ord(x) < 0x7F else '.' for x in s] if is_unicode else
                       [chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
        result.append(f"{i:04X}  {hexa:<{length * 3}}  {text}")
    
    print('\n'.join(result))


def receive_from(connection, timeout=10):
    buffer = b""
    connection.settimeout(timeout)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except socket.timeout:
        pass
    except Exception as e:
        print(f"Error while receiving data: {e}")
    return buffer


def request_handler(buffer, remote_host):
    # Modify the buffer if necessary before sending to the remote host
    try:
        # Decode buffer into a string to manipulate HTTP headers
        request = buffer.decode('utf-8', errors='ignore')

        # Split headers and body
        headers, body = request.split("\r\n\r\n", 1)

        # Modify headers
        lines = headers.split("\r\n")
        modified_headers = []
        for line in lines:
            if line.lower().startswith("host:"):
                # Replace Host header with the remote host from the command line
                modified_headers.append(f"Host: {remote_host}")
            else:
                modified_headers.append(line)

        # Reconstruct and return modified request
        modified_request = "\r\n".join(modified_headers) + "\r\n\r\n" + body
        return modified_request.encode('utf-8')
    except Exception as e:
        print(f"Error modifying HTTP request: {e}")
        return buffer


def response_handler(buffer):
    return buffer


def log_to_pcap_dpkt(pcap_writer, data, src_ip, dst_ip, src_port, dst_port, ts=None):
    """Log traffic to a PCAP file using dpkt with proper IP/TCP layers."""
    try:
        if not ts:
            ts = time.time()

        tcp = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=0,
            ack=0,
            flags=dpkt.tcp.TH_ACK,
            data=data,
        )

        ip = dpkt.ip.IP(
            src=socket.inet_aton(src_ip),
            dst=socket.inet_aton(dst_ip),
            p=dpkt.ip.IP_PROTO_TCP,  
            data=tcp,
        )
        ip.len = 20 + len(tcp)  

        eth = dpkt.ethernet.Ethernet(
            src=b"\xaa\xbb\xcc\xdd\xee\xff",  
            dst=b"\x11\x22\x33\x44\x55\x66",  
            type=dpkt.ethernet.ETH_TYPE_IP,  
            data=ip,
        )

        pcap_writer.writepkt(eth.pack(), ts=ts)
    except Exception as e:
        print(f"Error logging packet to PCAP: {e}")


def main():
    if len(sys.argv) != 6:
        print("Usage: ./proxy.py [local host] [local port] [remote host] [remote port] [first True or False]")
        print("Example: ./proxy.py 127.0.0.1 59932 example.com 443 True")
        sys.exit(0)
    sys.argv[-1] = sys.argv[-1].lower() == "true" 
    server_loop(*sys.argv[1:])

if __name__ == '__main__':
    main()