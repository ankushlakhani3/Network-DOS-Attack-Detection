from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
import time

log = core.getLogger()

# Configuration parameters
SYN_THRESHOLD = 100  # Number of SYN packets allowed before triggering action
THROUGHPUT_THRESHOLD = 20 * 1024 * 1024  # Data volume threshold (20 MB/sec)
BLOCK_DURATION = 10  # Block duration in seconds

class TrafficMonitor(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.syn_counts = {}  # Track SYN packets by source IP
        self.throughput_counts = {}  # Track total throughput (bytes) per source IP
        self.blocked_ips = {}  # Track blocked IPs

    def _handle_ConnectionUp(self, event):
        """Handles the event when a switch connects to the controller."""
        log.info(f"Switch {dpid_to_str(event.dpid)} has successfully connected to the network.")

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

        log.info(f"Incoming packet: {src_ip} -> {dst_ip}")

        # Check if the source IP is blocked
        if src_ip in self.blocked_ips:
            log.warning(f"Traffic from IP {src_ip} is currently blocked due to previous threshold breach. Dropping packet.")
            return

        # Count SYN packets (detecting potential SYN flood)
        if packet.find("tcp") and packet.find("tcp").flags == "S":  # SYN packet detection
            self.syn_counts[src_ip] = self.syn_counts.get(src_ip, 0) + 1
            log.debug(f"SYN packet count from {src_ip}: {self.syn_counts[src_ip]}")

            # Block IP if SYN threshold exceeded
            if self.syn_counts[src_ip] >= SYN_THRESHOLD:
                log.warning(f"Threshold exceeded: More than {SYN_THRESHOLD} SYN packets from {src_ip}. Blocking this IP.")
                self.block_ip(src_ip)

        # Track throughput (data volume)
        byte_count = len(str(packet))
        self.throughput_counts[src_ip] = self.throughput_counts.get(src_ip, 0) + byte_count
        log.debug(f"Data volume from {src_ip}: {self.throughput_counts[src_ip]} bytes")

        # Block IP if throughput exceeds threshold
        if self.throughput_counts[src_ip] >= THROUGHPUT_THRESHOLD:
            log.warning(f"Data volume from {src_ip} exceeds {THROUGHPUT_THRESHOLD} bytes/second. Blocking this IP.")
            self.block_ip(src_ip)

    def block_ip(self, ip):
        """Blocks the specified IP by adding a flow rule to drop packets from the source IP."""
        log.info(f"Blocking IP: {ip} for {BLOCK_DURATION} seconds.")

        # Block the IP by adding a flow rule on both switches (s1, s2)
        self.add_block_flow_rule(ip)

        # Record the blocked IP
        self.blocked_ips[ip] = time.time()

        # Unblock after the specified duration
        core.callLater(BLOCK_DURATION, self.unblock_ip, ip)

    def unblock_ip(self, ip):
        """Unblocks the IP by removing the flow rule."""
        log.info(f"Unblocking IP: {ip}.")
        self.remove_block_flow_rule(ip)

        # Remove from blocked IPs
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]

    def add_block_flow_rule(self, ip):
        """Adds a flow rule to block the traffic from the given IP."""
        # Creating the flow rule to drop packets from the specified IP
        msg = of.ofp_flow_mod()
        msg.match.nw_src = IPAddr(ip)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        log.debug(f"Adding flow rule to block IP {ip}.")
        core.openflow.sendToSwitch(dpid_to_str(1), msg)  # Assuming Switch 1
        core.openflow.sendToSwitch(dpid_to_str(2), msg)  # Assuming Switch 2

    def remove_block_flow_rule(self, ip):
        """Removes the flow rule that blocks traffic from the given IP."""
        # Creating the flow rule to remove the block on the IP
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.nw_src = IPAddr(ip)
        log.debug(f"Removing flow rule to unblock IP {ip}.")
        core.openflow.sendToSwitch(dpid_to_str(1), msg)  # Assuming Switch 1
        core.openflow.sendToSwitch(dpid_to_str(2), msg)  # Assuming Switch 2

def launch():
    """Launches the POX controller and starts monitoring traffic."""
    log.info("Traffic Monitoring started. Monitoring SYN floods and throughput breaches.")
    core.registerNew(TrafficMonitor)
