from socket import socket, AF_INET, SOCK_STREAM
from threading import local
from typing import Tuple, Optional

from .messages import *

class Session(object):
	def __init__(self, ipv4s: list, ipv6s: list) -> None:
		self.sock = None
		self.server = None
		self.server_peer = None
		self.client_peer = None
		self.ipv4s = ipv4s
		self.ipv6s = ipv6s

	# step 0, connect :D
	def connect(self, server: Tuple[str, int]) -> None:
		if self.sock is not None:
			self.sock.close()

		self.sock = socket(AF_INET, SOCK_STREAM)
		self.sock.connect(server)

		self.server = server

		print("connected to %s:%d ..." % (self.server[0], self.server[1]))

	# step 1, start the handshake with the server, exchange peer information
	def handshake(self, peer_id: str = None, peer_name: str = None) -> None:
		print("initiating handshake sequence")
		# client.Hello
		cli_hello = Hello.build(peer_id, peer_name)
		print("> client.", end='')
		cli_hello.print()
		self.sock.sendall(cli_hello.to_raw_data())
		
		self.client_peer = cli_hello.peer_id

		# server.Ack
		ack = Ack.from_reader(self.sock) 
		print("< server.", end='')
		ack.print()

		# server.Hello
		srv_hello = Hello.from_reader(self.sock)
		print("< server.", end='')
		srv_hello.print()

		self.server_peer = srv_hello.peer_id
		self.server_peer.print()

		# client.Ack
		ack = Ack.build(0x00010000) # i_have_no_idea_what_im_doing.gif
		print("> client.", end='')
		ack.print()
		self.sock.sendall(ack.to_raw_data())

		# client.Accept
		accept = Accept.build(0x00) # i_have_no_idea_what_im_doing.gif
		print("> client.", end='')
		accept.print()
		self.sock.sendall(accept.to_raw_data())

	# step 2, send an invitation
	def invite(self) -> None:
		print("sending invitation")

		# client.Invite
		invite = Invite.build(self.server_peer, self.client_peer)
		print("> client.", end='')
		invite.print()
		self.sock.sendall(invite.to_raw_data())

		# server.Ack
		ack = Ack.from_reader(self.sock) 
		print("< server.", end='')
		ack.print()
	
	# step 3, wait for the server to authorize the invitation
	def wait_invitation_response(self) -> InviteResponse:
		print("waiting invitation response ...")

		while True:
			# we could receive an Ack (0 payload size), or the header of the InviteResponse
			what = Header.from_reader(self.sock)
			if not what.has_payload():
				# just a server.Ack
				ack = Ack(what)
				print("< server.", end='')
				ack.print()
			else:
				# server.InvitationResponse		
				response = InviteResponse.from_reader(what, self.sock)
				print("< server.", end='')
				response.print()

				# client.Ack
				ack = Ack.build_with_signature(InviteResponse.SIGNATURE, 0x00)
				self.sock.sendall(ack.to_raw_data())
				print("> client.", end='')
				ack.print()

				return response

	# step 4, once our invitation has been accepted, send our client data response
	def send_client_data(self, server_response: InviteResponse):
		print("sending client data for [%s] / [%s]" % (self.ipv4s, self.ipv6s))

		# create client response from the server response
		client_response = InviteClientData.from_server_response(server_response, self.ipv4s, self.ipv6s)
		self.sock.sendall(client_response.to_raw_data())
		print("> client.", end='')
		client_response.print()

		# read server ack
		ack = Ack.from_reader(self.sock) 
		print("< server.", end='')
		ack.print()

		# read second server ack
		
		ack = Ack.from_reader(self.sock) 
		print("< server.", end='')
		ack.print()

		# keep reading ...
		while True:
			data = self.sock.recv(1024)
			if len(data) > 0:
				print("< server.", end='')
				hexdump(data)