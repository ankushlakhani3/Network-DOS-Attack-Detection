from scapy.all import *
import random
import time

def send_http_request(src_ip, target_ip, target_port=80):
    """
    Function to send an HTTP GET request to the target server.
    """
    # Build IP and TCP packet for HTTP GET request
    ip_packet = IP(src=src_ip, dst=target_ip)
    tcp_packet = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S", seq=random.randint(1000, 9000))

    # Send SYN to initiate TCP handshake
    syn_packet = ip_packet / tcp_packet
    send(syn_packet, verbose=False)

    # Send ACK to complete TCP handshake
    ack_packet = ip_packet / TCP(sport=tcp_packet.sport, dport=target_port, flags="A", ack=tcp_packet.seq + 1)
    send(ack_packet, verbose=False)

    # Send HTTP GET request
    http_request = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
    http_packet = ip_packet / TCP(sport=tcp_packet.sport, dport=target_port, flags="A", ack=tcp_packet.seq + 1) / Raw(load=http_request)
    send(http_packet, verbose=False)

    print(f"HTTP request sent from {src_ip} to {target_ip}")

def normal_traffic_flow_to_server():
    """
    Function to simulate normal traffic flow from hosts (h1 to h6) to the server (h3).
    """
    server_ip = "10.0.0.3"  # IP of the server (h3)
    hosts_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5", "10.0.0.6"]  # IPs of h1 to h6

    print("Simulating normal traffic flow from h1 to h6 to the server h3...\n")

    # Send HTTP requests from each host
    for src_ip in hosts_ips:
        send_http_request(src_ip, server_ip)
        time.sleep(1)  # Slight delay between requests to simulate normal traffic

    print("\nNormal traffic simulation complete.")

if __name__ == "__main__":
    normal_traffic_flow_to_server()
