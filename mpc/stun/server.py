#!/usr/bin/env python3
from typing import Tuple
import socket
import threading
import random

import netifaces

import mpc.stun.messages as stun
import mpc.ospf.session as ospf
import mpc.utils as utils

def stun_worker(address: str, port: int) -> None:
	if ':' in address:
		bind_to = utils.get_ipv6_bind_address(address, port)
		family = socket.AF_INET6
	else:
		bind_to = (address, port)
		family = socket.AF_INET

	stund = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	stund.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	stund.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	stund.bind(bind_to)

	print("[STUN] udp server started on %s:%d" % (address, port))

	# start STUN sequence

	# read binding request from server
	rcvd_from_address, server_bind_request = stun.Message.from_udp_socket(stund)
	print()
	print("< server.", end='')
	server_bind_request.print(True)
	assert( server_bind_request.is_binding_request() )

	# create and send our own binding request
	client_bind_request = stun.binding_request_from(server_bind_request)
	print("> client.", end='')
	client_bind_request.print(True)
	stund.sendto( client_bind_request.to_raw_data(), rcvd_from_address)

	# read server binding response
	rcvd_from_address, server_bind_response = stun.Message.from_udp_socket(stund)
	print("< server.", end='')
	server_bind_response.print(True)
	assert( server_bind_response.is_successfull_binding_response_to(client_bind_request) )

	# send our binding response 
	# the second and third arguments indicate the source IP address and port the server saw in the Binding Request
	# ref https://www.3cx.com/blog/voip-howto/stun-details/
	client_bind_response = stun.binding_response_for(server_bind_request, rcvd_from_address[0], rcvd_from_address[1])
	print("> client.", end='')
	client_bind_response.print(True)
	assert( client_bind_response.is_successfull_binding_response_to(server_bind_request))
	stund.sendto( client_bind_response.to_raw_data(), rcvd_from_address)

	# send another binding request with extra attributes
	client_bind_request_with_extra = stun.binding_request_from(server_bind_request, 
		# as seen on wireshark
		extra_attributes=[
			stun.Attribute.build( stun.USE_CANDIDATE_ATTRIBUTE, 0, bytes([]) ),
			stun.Attribute.build( stun.APPLE_ATTRIBUTE_8008, 4, bytes([0x00, 0x00, 0x06, 0x01]) )
		],
		tie_breaker=client_bind_request.get_tie_breaker()
	)
	print("> client.", end='')
	client_bind_request_with_extra.print(True)
	stund.sendto( client_bind_request_with_extra.to_raw_data(), rcvd_from_address)

	# read server response
	rcvd_from_address, server_bind_response_2 = stun.Message.from_udp_socket(stund)
	print("< server.", end='')
	server_bind_response_2.print(True)
	assert( server_bind_response_2.is_successfull_binding_response_to(client_bind_request_with_extra) )

	print("[STUN] binding complete")

	# we're done with STUN things, let's talk OSPF!
	ospf.start_session(stund, rcvd_from_address)


def start_for_iface(iface: str, port: int, with_ipv6 = True) -> Tuple[Tuple[str, int], Tuple[str, int]]:
	ipv4s = []
	ipv6s = []

	# use same port for all with SO_REUSEADDR and SO_REUSEPORT
	port = random.randint(15000, 17000) 

	# for each ipv4 and ipv6 addresses on this interface
	for _, info in netifaces.ifaddresses(iface).items():
		if len(info) == 0:
			continue

		info = info[0]
		if 'netmask' in info and 'addr' in info:
			# get ip and generate random port
			ip = info['addr']
			if ':' in ip:
				if not with_ipv6:
					continue
				# ipv6, we need the interface name for binding but not for transmission
				ipv6s.append((ip.replace('%%%s' % iface, ''), port))
			else:
				# ipv4
				ipv4s.append((ip, port))
			# start server thread
			threading.Thread(target=stun_worker, args=(ip, port,)).start()

	return (ipv4s, ipv6s)