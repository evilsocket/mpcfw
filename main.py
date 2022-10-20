#!/usr/bin/env python3
import sys
import random

import mpc.mdns as mdns
import mpc.tcp.protocol as tcp_protocol
import mpc.stun.server as stund
import mpc.utils as utils

# search for an MPC service by listening to mDNS packets broadcasted on the network
service = mdns.discover()

print()

# start the STUN udp server for each ip of the interface, for simplicity let's only use IPv4
# use the same random port for all with SO_REUSEADDR and SO_REUSEPORT
iface = 'en4'
port = random.randint(15000, 17000) 

(ipv4s, _) = stund.start_for_iface(iface, port, with_ipv6=False)

# start the tcp session
tcp_session = tcp_protocol.Session(ipv4s, []) 
tcp_session.connect((service.address, service.port))

print()

peer_name = utils.random_peer_name() if len(sys.argv) < 2 else sys.argv[1]
peer_id = utils.random_peer_id()

tcp_session.handshake(peer_id, peer_name)

print()

tcp_session.invite()

print()

response = tcp_session.wait_invitation_response()
if not response.accepted:
    print("the server declined the invitation :(")
    quit()

print("the server accepted the invitation")

# this will block and the ICE server will start receiving STUN via UDP
tcp_session.send_client_data(response)