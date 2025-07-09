from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
import time
import threading

log = core.getLogger()

# Configuration parameters
SYN_THRESHOLD = 100  # Number of SYN packets allowed per second before triggering action
THROUGHPUT_THRESHOLD = 20 * 1024 * 1024  # Data volume threshold (20 MB/sec)
BLOCK_DURATION = 10  # Block duration in seconds

class TrafficMonitor(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.syn_counts = {}  # Track SYN packets by source IP
        self.throughput_counts = {}  # Track total throughput (bytes) per source IP
        self.blocked_ips = {}  # Track blocked IPs

        # Start the periodic reset of SYN counts
        self.reset_timer = threading.Timer(1.0, self.reset_syn_counts)
        self.reset_timer.start()

    def reset_syn_counts(self):
        """Reset SYN packet counts every second, except for blocked IPs."""
        for ip in list(self.syn_counts.keys()):
            if ip not in self.blocked_ips:
                self.syn_counts[ip] = 0
        self.reset_timer = threading.Timer(1.0, self.reset_syn_counts)
        self.reset_timer.start()

    def _handle_ConnectionUp(self, event):
        """Handles the event when a switch connects to the controller."""
        log.info(f"Switch {dpid_to_str(event.dpid)} has successfully connected to the network.")

        # Add a default flow to handle ARP and ICMP packets locally
        msg = of.ofp_flow_mod()
        msg.priority = 100  # High priority for ARP and ICMP
        msg.match = of.ofp_match(dl_type=0x0806)  # ARP packets
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.match = of.ofp_match(dl_type=0x0800, nw_proto=1)  # ICMP packets
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        """Handles incoming packets from switches and applies traffic monitoring logic."""
        packet = event.parsed

        # Ensure packet is properly parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete or malformed packet.")
            return

        # Extract IP packet details
        ip_packet = packet.find("ipv4")
        if not ip_packet:
            return  # Non-IP packet, ignoring

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        if src_ip in self.blocked_ips:
            log.warning(f"Packet from blocked IP {src_ip} dropped.")
            return

        # Check for SYN packets in TCP
        tcp_packet = packet.find("tcp")
        if tcp_packet and tcp_packet.SYN and not tcp_packet.ACK:
            # Increment SYN count for the source IP
            self.syn_counts[src_ip] = self.syn_counts.get(src_ip, 0) + 1
            log.info(f"Source IP {src_ip} SYN count: {self.syn_counts[src_ip]}")

            if self.syn_counts[src_ip] > SYN_THRESHOLD:
                log.warning(f"Threshold exceeded: {src_ip} has sent more than {SYN_THRESHOLD} SYN packets per second.")
                self._block_ip(src_ip)

        # Track data throughput (bytes) per source IP
        bytes_in_packet = len(packet)
        self.throughput_counts[src_ip] = self.throughput_counts.get(src_ip, 0) + bytes_in_packet
        log.info(f"Data throughput for {src_ip}: {self.throughput_counts[src_ip]} bytes/sec")

        if self.throughput_counts[src_ip] > THROUGHPUT_THRESHOLD:
            log.warning(f"Data throughput exceeded: {src_ip} has sent more than {THROUGHPUT_THRESHOLD} bytes/sec.")
            self._block_ip(src_ip)

    def _block_ip(self, ip):
        """Block the source IP by adding it to the blocked list."""
        if ip in self.blocked_ips:
            log.debug(f"IP {ip} is already blocked. Skipping.")
            return

        self.blocked_ips[ip] = time.time()
        log.info(f"Blocking IP {ip} for {BLOCK_DURATION} seconds.")

        # Trigger cleanup after BLOCK_DURATION seconds
        threading.Timer(BLOCK_DURATION, self._unblock_ip, [ip]).start()

    def _unblock_ip(self, ip):
        """Unblock the source IP after the block duration has passed."""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            log.info(f"Unblocked IP {ip}.")

def launch():
    """Launch the Traffic Monitor module."""
    traffic_monitor = TrafficMonitor()
    log.info("Traffic Monitor started.")
