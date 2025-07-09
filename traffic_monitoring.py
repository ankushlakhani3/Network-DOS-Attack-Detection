from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
import time

log = core.getLogger()

# Configuration parameters
SYN_THRESHOLD = 100  # Number of SYN packets allowed before blocking
BLOCK_DURATION = 10   # Block duration in seconds

class TrafficMonitor(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.syn_counts = {}  # Track SYN packets by source IP
        self.blocked_ips = {}  # Track blocked IPs

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {dpid_to_str(event.dpid)} connected.")

    def _handle_PacketIn(self, event):
        packet = event.parsed

        # Ensure the packet is parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet.")
            return

        # Extract IP layer
        ip_packet = packet.find("ipv4")
        if not ip_packet:
            return  # Non-IP packet, ignore

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        log.info(f"Packet: {src_ip} -> {dst_ip}")

        if src_ip in self.blocked_ips:
            log.warning(f"Blocked packet from {src_ip}. Dropping packet.")
            return

        # Check for SYN packets in TCP
        tcp_packet = packet.find("tcp")
        if tcp_packet and tcp_packet.SYN and not tcp_packet.ACK:
            log.debug(f"Packet being transferred having IP adresses: {src_ip} -> {dst_ip}")
            self.syn_counts[src_ip] = self.syn_counts.get(src_ip, 0) + 1

            if self.syn_counts[src_ip] > SYN_THRESHOLD:
                log.warning(f"!!!!!! Detected SYN flood from {src_ip}. Blocking IP. !!!!!!!!!")
                self.block_ip(event.connection, src_ip)
                return

        # Forward normal traffic
        self.forward_packet(event)

    def forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port
        event.connection.send(msg)
        log.debug("Packet forwarded normally.")

    def block_ip(self, connection, ip):
        if ip in self.blocked_ips:
            log.warning(f"IP {ip} is already blocked.")
            return

        log.info(f"!!!!!!!!! Blocking IP {ip}.")
        self.blocked_ips[ip] = time.time() + BLOCK_DURATION

        # Add flow rule to drop packets from the blocked IP
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800  # Ethernet type for IPv4
        msg.match.nw_src = IPAddr(ip)
        msg.actions = []  # No actions = Drop packets
        connection.send(msg)
        log.debug(f"Flow rule added to block IP {ip}.")

        # Schedule unblock
        core.callDelayed(BLOCK_DURATION, self.unblock_ip, connection, ip)

    def unblock_ip(self, connection, ip):
        if ip not in self.blocked_ips:
            log.error(f"IP {ip} is not currently blocked.")
            return

        log.info(f"Unblocking IP {ip}.")
        del self.blocked_ips[ip]

        # Remove flow rule for the blocked IP
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800  # Ethernet type for IPv4
        msg.match.nw_src = IPAddr(ip)
        msg.command = of.OFPFC_DELETE
        connection.send(msg)
        log.debug(f"Flow rule removed for IP {ip}.")

def launch():
    core.registerNew(TrafficMonitor)

# h3 python3 -m http.server 80 &

# sudo mn --custom topology.py --topo custom --controller remote --mac

# ssh mininet@localhost -p 2223

# h1 iperf -c 10.0.0.3 -u -b 10M -t 60

# ./pox.py log.level --DEBUG controller_s

# h2 python3 /tmp/normal_traffic_flow.py

# h2 python3 /tmp/flood.py

# sudo cp flood.py /tmp/

# sudo cp normal.py /tmp/

# ps aux | grep pox

# kill - 9 ID
