# used for type hints, requires python3.7+
from __future__ import annotations
from calendar import c
from http import server
from typing import Tuple
import zlib
import base36
import plistlib
import random
import struct
from socket import socket, inet_ntop, inet_pton, AF_INET, AF_INET6

from hexdump import hexdump

from mpc.utils import Struct

# message header, this is common to all messages
class Header(Struct):
	CONST_SIZE = 16

	@staticmethod
	def from_reader(reader: socket) -> Header:
		# given its constant size, we can read it in a single operation
		data = reader.recv(Header.CONST_SIZE)
		if len(data) != Header.CONST_SIZE:
			raise Exception('error while reading message header, expected %d bytes, got %d' % (Header.CONST_SIZE, len(data)))
		# parse the data
		header = Header()
		header.parse_raw_data(data)
		# done
		return header
	
	@staticmethod 
	def build(signature: bytes, maybe_seqn: int, payload_size=0) -> Header:
		header = Header()
		header._cfields['signature'] = signature 
		header._cfields['maybe_seqn'] = maybe_seqn 
		header._cfields['payload_size'] = payload_size 
		return header

	def has_payload(self) -> bool:
		return self._cfields['payload_size'] > 0

	def checksum(self) -> int:
		return self._cfields['crc32']

	def fix_checksum(self) -> None:
		self._cfields['crc32'] = 0x00
		without_crc = self.to_raw_data()
		self._cfields['crc32'] = zlib.crc32(without_crc)		

	def __init__(self):
		super(Header, self).__init__( 'header',
		(
			( 'signature',     'H' ), # identifies the message type
            ( 'maybe_seqn',    'I' ), # it seems related to the message this is a response to
            ( 'payload_size',  'H' ), # size of the payload after this header, if any
            ( 'crc32',         'I' ), # checksum of the whole message body (with this field set to 0)
            ( 'unk_1',         'I' ), # no freaking idea
		))

# a payload describing a peer identification info: 
#	peer_id.identifier() is a base36 encoded random number
#   peer_id.name() is any string representing the display name of the host (iPhone name for instance)
# ref https://developer.apple.com/documentation/multipeerconnectivity/mcpeerid
class PeerID(Struct):
	@staticmethod
	def build(identifier : str, name : str, flags : int = 0x06) -> PeerID:
		peer_id = PeerID()
		peer_id._identifier = identifier
		peer_id._name = name
		peer_id._cfields['flags'] = flags
		peer_id._cfields['length'] = len(peer_id.peer_string())
		return peer_id

	def __init__(self):
		super(PeerID, self).__init__(
			'peer_id',
			(
				( 'flags',  'I' ), # still not sure, it might indicate payload type (always 0x6 for a PeerID payload)
				( 'length', 'H' )  # length of the data section of this payload 
		))
		self._identifier = None
		self._name = None

	def identifier(self) -> str:
		return self._identifier

	def numeric_identifier(self) -> int:
		return base36.loads(self._identifier)

	def name(self) -> str:
		return self._name

	def display(self) -> str:
		return 'peer(id=%s(0x%x) name=%s)' % (self._identifier, base36.loads(self._identifier), self._name)

	def peer_string(self) -> bytes:
		return str.encode(self._identifier) + \
				b'+' + \
				str.encode(self._name) + \
				b'\x00'

	def set_identifier(self, ident: str) -> None:
		self._identifier = ident
		self._cfields['length'] = len(self.peer_string())

	def set_name(self, name: str) -> None:
		self._name = name
		self._cfields['length'] = len(self.peer_string())

	def parse_raw_data(self, data: bytes) -> None:
		super(PeerID, self).parse_raw_data(data)

		try:
			self._identifier, self._name = data[self._csize:].decode('utf-8').rstrip('\x00').split('+')
		except Exception as e:
			print("can't decode peer_id name data:\n\n%s\n" % hexdump(data, 'return'))
			raise e

	def to_raw_data(self) -> bytes:
		return super(PeerID, self).to_raw_data() + self.peer_string()

	# in order to be transmitted as part of a bplist, a PeerID
	# object is encoded in a more concise binary format
	def to_bplist_encoding(self) -> bytes:
		# convert base36 string to the original number 
		b36_id = self._identifier
		num_id = base36.loads(b36_id)
		name = self._name.encode('raw_unicode_escape') # needed to support unicode names, like emojis! :D

		return bytes(
			# encode the numeric peer id as bytes, big endian
			list(num_id.to_bytes(8, 'big'))
			+ 
			# name length
			[ len(name) & 0xff ]
			+
			# name bytes
			list(name)
		)

	def identifier_as_32bit(self):
		as_64 = self.numeric_identifier()
		tmp = ((as_64 >> 32) << 32) # shift it right then left 32 bits, which zeroes the lower half of the long
		return as_64 - tmp

	@staticmethod
	def from_bplist_encoding(encoded) -> PeerID:
		# get integer peer_id from first four bytes
		num_id = int.from_bytes(encoded[:8], 'big')
		# encode to base36
		b36_id = base36.dumps(num_id)
		# get name length
		name_len = encoded[8]
		# get decoded name
		name = encoded[9:9 + name_len].decode('raw_unicode_escape')
		# done
		return PeerID.build(b36_id, name)

	def print(self) -> None:
		print("  @peer_id")
		super(PeerID, self).print()

		id_as_int = base36.loads(self._identifier)
		id_as_bytes = id_as_int.to_bytes(8, 'big').hex()

		print("    identifier : %s [ base36(%d), raw=0x%s ]" % (self._identifier, id_as_int, id_as_bytes))
		print("    name       : %s" % self._name)

# client or server hello message, contains an Header and a PeerID payload describing the host.
class Hello(object):
	SIGNATURE = 0x07d0 # same as Ack

	@staticmethod
	def from_raw_data(data: bytes) -> Hello:
		header = Header()
		header.parse_raw_data(data)
		
		peer_id = PeerID()
		peer_id.parse_raw_data(data[header._csize:])

		return Hello(header, peer_id)

	@staticmethod
	def from_reader(reader : socket) -> Hello:
		# first read the header as it's constant in size
		header = Header.from_reader(reader)
		# validate expected signature
		if header.signature != Hello.SIGNATURE:
			raise Exception('expected Hello header signature 0x%x, got 0x%x' % (Hello.SIGNATURE, header.signature))
		# validate payload size
		if header.payload_size == 0:
			raise Exception('expected payload for Hello message, but payload_size is 0')
		# read the payload
		payload = reader.recv(header.payload_size)
		if len(payload) != header.payload_size:
			raise Exception('could not read Hello payload of size %d, got %d bytes' % (header.payload_size, len(payload)))
		# parse the payload as PeerID
		peer_id = PeerID()
		peer_id.parse_raw_data(payload)
		# done
		return Hello(header, peer_id)

	@staticmethod
	def build(peer_identifier: str, peer_name: str, peer_id_flags : int = 0x06) -> Hello:
		peer_id = PeerID.build(peer_identifier, peer_name, peer_id_flags)
		header = Header.build(Hello.SIGNATURE, 0x00, peer_id._csize + peer_id.length)
		
		msg = Hello(header, peer_id)
		msg.fix_checksum()

		return msg
	
	def __init__(self, header: Header, peer_id: PeerID):
		self.header = header
		self.peer_id = peer_id

	def fix_checksum(self) -> None:
		self.header._cfields['crc32'] = 0x00
		without_crc = self.to_raw_data()
		self.header._cfields['crc32'] = zlib.crc32(without_crc)

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + self.peer_id.to_raw_data()

	def print(self, full=False) -> None:
		print("@hello")
		if full:
			print("  @header")
			self.header.print()
			self.peer_id.print()

# acknowledge message sent after a packet is received by one of the two ends, no data, just header
class Ack(object):
	SIGNATURE = 0x07d0 # same as Hello
	CONST_SIZE = Header.CONST_SIZE

	@staticmethod
	def from_raw_data(data: bytes) -> Ack:
		header = Header()
		header.parse_raw_data(data)
		return Ack(header)

	@staticmethod
	def from_reader(reader: socket) -> Ack:
		header = Header.from_reader(reader)
		return Ack(header)		

	def __init__(self, header : Header):
		self.header = header

	@staticmethod
	def build_with_signature(signature : int, maybe_seqn : int) -> Ack:
		header = Header.build(signature, maybe_seqn, 0x00)
		msg = Ack(header)
		msg.fix_checksum()
		return msg

	@staticmethod
	def build(maybe_seqn : int) -> Ack:
		return Ack.build_with_signature(Ack.SIGNATURE, maybe_seqn)

	def fix_checksum(self) -> None:
		self.header.fix_checksum()

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data()

	def print(self, full=False) -> None:
		print("@ack")
		if full:
			print("  @header")
			self.header.print()

# MCFrameworks logs refer to this message as Accept, it's sent after the client and server Hellos
# right before the client starts sending the Invite message.
class Accept(object):
	CONST_SIZE = Header.CONST_SIZE
	SIGNATURE = 0x0898 

	@staticmethod
	def from_raw_data(data: bytes) -> Accept:
		header = Header()
		header.parse_raw_data(data)
		return Accept(header)

	@staticmethod
	def from_reader(reader: socket) -> Accept:
		header = Header.from_reader(reader)
		return Accept(header)		

	def __init__(self, header: Header):
		self.header = header

	@staticmethod
	def build(maybe_seqn: int) -> Accept:
		header = Header.build(Accept.SIGNATURE, maybe_seqn, 0x00)
		msg = Accept(header)
		msg.fix_checksum()
		return msg

	def fix_checksum(self) -> None:
		self.header.fix_checksum()

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data()

	def print(self, full=False) -> None:
		print("@accept")
		if full:
			print("  @header")
			self.header.print()

# represents the bplist encoded invited data sent as part of the Invite message.
class InviteData(object):
	def __init__(self, server_peer_id: PeerID, client_peer_id: PeerID):
		self.context = 0x2 # always 2
		self.invite_id = 0x0 # always 0
		self.message_id = 0x1 # always 1
		self.server_peer_id = server_peer_id # recipient
		self.client_peer_id = client_peer_id # sender

	def to_dict(self) -> dict:
		encoded_sender_id = self.client_peer_id.to_bplist_encoding()
		encoded_recpt_id = self.server_peer_id.to_bplist_encoding()
		return {
			'MCNearbyServiceInviteContextKey': plistlib.dumps(self.context, fmt = plistlib.FMT_BINARY),
			'MCNearbyServiceInviteIDKey': self.invite_id,
			'MCNearbyServiceMessageIDKey': self.message_id,
			'MCNearbyServiceRecipientPeerIDKey': encoded_recpt_id,
			'MCNearbyServiceSenderPeerIDKey': encoded_sender_id,
		}

	def to_xml_plist(self) -> bytes:
		return plistlib.dumps(self.to_dict(), fmt = plistlib.FMT_XML)

	def to_binary_plist(self) -> bytes:
		return plistlib.dumps(self.to_dict(), fmt = plistlib.FMT_BINARY)

	def print(self) -> None:
		print("  @data")
		print("%s" % self.to_xml_plist())

# This message is quite convoluted compared to the previous ones.
# It contains the standard header, plus a binary encoded plist containing
# basically the same data that the peers already exchanged in the Hello
# messages. Sent from the client to invite the server to the party, if
# the client is not already known it will trigger an 'Accept/Decline' 
# dialog, otherwise the invitation will be accepted silently.
class Invite(object):
	SIGNATURE = 0x0834

	@staticmethod
	def build(server_peer_id: PeerID, client_peer_id: PeerID) -> Invite:
		data = InviteData(server_peer_id, client_peer_id)
		header = Header.build(Invite.SIGNATURE, 0x00, len(data.to_binary_plist()))
		
		msg = Invite(header, data)
		msg.fix_checksum()

		return msg
	
	def __init__(self, header: Header, data: InviteData):
		self.header = header
		self.data = data

	def fix_checksum(self) -> None:
		self.header._cfields['crc32'] = 0x00
		without_crc = self.to_raw_data()
		self.header._cfields['crc32'] = zlib.crc32(without_crc)

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + self.data.to_binary_plist()

	def print(self, full=False) -> None:
		print("@invite")
		if full:
			print("  @header")
			self.header.print()
			self.data.print()

# ConnectionData.header object, used to describe payload security (encryption and authenticaiton),
# total data size and how many entries there are in the following bytes.
class ConnectionDataHeader(Struct):
	SIGNATURE = 0x80

	CONST_SIZE = 5

	# bit masks for security field
	ENCRYPTION_NONE = 0b00000010
	ENCRYPTION_REQUIRED = 0b00000001
	ENCRYPTION_OPTIONAL = 0b00000000
	AUTHENTICATION_ENABLED = 0b00000100
	AUTHENTICATION_DISABLED = 0b00000000

	def __init__(self, raw_data = None):
		super(ConnectionDataHeader, self).__init__(
			'connection_data.header',
			(
				( 'signature', 'B' ), # 0x80
				( 'security',  'B' ), # encryption enabled and auth enabled mask
				( 'data_size', 'H' ), # total data size
				( 'entries',   'B' ), # number of entries ( first 4 bits for n of ipv4, last 4 bits for n of ipv6 )
		))

		if raw_data is not None:
			self.parse_raw_data(raw_data)
	
	def parse_raw_data(self, data: bytes) -> None:
		super(ConnectionDataHeader, self).parse_raw_data(data)
		# do some validation
		if self._cfields['signature'] != ConnectionDataHeader.SIGNATURE:
			raise Exception('expected ConnectionDataHeader signature 0x%x, got 0x%x' % ( 
				ConnectionDataHeader.SIGNATURE, 
				self._cfields['signature']))

		num_ipv4 = self.ipv4_num_entries()
		num_ipv6 = self.ipv6_num_entries()
		num_segments = num_ipv4 + num_ipv6
		expected_size = ConnectionDataHeader.CONST_SIZE + \
						4 * num_ipv4 + \
						16 * num_ipv6 + \
						ConnectionDataSegment.CONST_SIZE * num_segments

		if self._cfields['data_size'] != expected_size:
			raise Exception('expected ConnectionDataHeader size %d, got %d' % ( 
				expected_size, 
				self._cfields['data_size']))

	@staticmethod
	def build(encryption: int, authentication: int, ipv4_entries: int, ipv6_entries) -> ConnectionDataHeader:
		header = ConnectionDataHeader()

		num_segments = ipv4_entries + ipv6_entries

		header._cfields['signature'] = ConnectionDataHeader.SIGNATURE
		header._cfields['security'] = encryption | (authentication << 4)
		header._cfields['data_size'] = ConnectionDataHeader.CONST_SIZE + \
										4 * ipv4_entries + \
										16 * ipv6_entries + \
										ConnectionDataSegment.CONST_SIZE * num_segments
		header._cfields['entries'] = ipv6_entries | (ipv4_entries << 4)

		return header

	def encryption_type(self):
		if self._cfields['security'] & ConnectionDataHeader.ENCRYPTION_NONE:
			return 'none'
		elif self._cfields['security'] & ConnectionDataHeader.ENCRYPTION_REQUIRED:
			return 'required'
		else:
			return 'optional'
	
	def auth_enabled(self):
		# third lsb: authentication enabled (yes = 1XX, no = 0XX)
		return True if self._cfields['security'] & ConnectionDataHeader.AUTHENTICATION_ENABLED else False

	def ipv4_num_entries(self):
		return self._cfields['entries'] >> 4

	def ipv6_num_entries(self):
		return self._cfields['entries'] & 0b00001111

	def print(self) -> None:
		print("    @connection_data.header")
		#super( ConnectionDataHeader, self ).print()
		#print("    --")
		print("      encryption: %s" % self.encryption_type())
		print("      authentication: %s" % self.auth_enabled())
		print("      ipv4 entries: %d" % self.ipv4_num_entries())
		print("      ipv6 entries: %d" % self.ipv6_num_entries())

# One element of ConnectionData.segments, for each network interface (ip, port, participant_id)
# this object describes the properties of it.
class ConnectionDataSegment(Struct):
	SIGNATURE = 0x61

	CONST_SIZE = 16

	IFACE_TYPE_IPV4 = 0x5A
	IFACE_TYPE_IPV6 = 0x0A

	IFACE_INDEX_IPV4_MASK = 0x80
	IFACE_INDEX_IPV6_MASK = 0x90

	def __init__(self, raw_data = None):
		super(ConnectionDataSegment, self).__init__(
			'connection_data.segment',
			(
				( 'signature',      'B' ), # 0x61
				( 'participant_id', 'I' ), # client or server peer id as 32 bits integer
				( 'rand_data',      'I' ), # my guess is that this creates a new unique identifier together with participant_id
				( 'iface_type',     'B' ), # ipv4=0x5A ipv6=0x0A
				( 'padding',       '3s' ), # probably part of iface_index, but we're ready in reverse so it's useful to split them
				( 'iface_index',    'B' ), # index of the interface in the ip list combined with type (again)
				( 'port',           'H' ), # udp port
		),
		'<') # this is the only little-endian structure

		if raw_data is not None:
			self.parse_raw_data(raw_data)

	@staticmethod
	def build(participant_id : int, iface_type: int, iface_index: int, port: int) -> ConnectionDataSegment:
		idx_mask = (ConnectionDataSegment.IFACE_INDEX_IPV4_MASK 
					if iface_type == ConnectionDataSegment.IFACE_TYPE_IPV4
					else ConnectionDataSegment.IFACE_INDEX_IPV6_MASK)

		segment = ConnectionDataSegment()
		segment._cfields['signature'] = ConnectionDataSegment.SIGNATURE
		segment._cfields['participant_id'] = participant_id
		segment._cfields['rand_data'] = random.randint(0, 4294967296)
		segment._cfields['iface_type'] = iface_type
		segment._cfields['padding'] = bytes([0, 0, 0])
		segment._cfields['iface_index'] = idx_mask | iface_index
		segment._cfields['port'] = port

		return segment 

	def parse_raw_data(self, data: bytes) -> None:
		super(ConnectionDataSegment, self).parse_raw_data(data)
		# do some validation
		if self._cfields['signature'] != ConnectionDataSegment.SIGNATURE:
			raise Exception('expected ConnectionDataSegment signature 0x%x, got 0x%x' % ( 
				ConnectionDataSegment.SIGNATURE, 
				self._cfields['signature']))

		if self._cfields['iface_type'] not in (ConnectionDataSegment.IFACE_TYPE_IPV4, ConnectionDataSegment.IFACE_TYPE_IPV6):
			raise Exception('ConnectionDataSegment.iface_type is neither of 0x%x or 0x%x, got 0x%x' % ( 
				ConnectionDataSegment.IFACE_TYPE_IPV4, 
				ConnectionDataSegment.IFACE_TYPE_IPV6, 
				self._cfields['iface_type']))

	def iface_type(self):
		return 'IPv4' if self._cfields['iface_type'] == ConnectionDataSegment.IFACE_TYPE_IPV4 else 'IPv6'

	def iface_index(self):
		return self._cfields['iface_index'] & 0b00001111

	def print(self):
		print("  @connection_data.segment")
		#super( ConnectionDataSegment, self ).print()
		#print("    --")
		print("    participant_id: 0x%x" % self._cfields['participant_id'])
		print("    iface type: %s" % self.iface_type())
		print("    iface index: %d" % self.iface_index())
		print("    port: %d" % self._cfields['port'] )

# The main ConnectionData object, made of a ConnectionDataHeader, then a block of raw ip addresses and
# then a list of ConnectionDataSegment objects describing each ip address.
class ConnectionData(object):
	def __init__(self, raw_data = None):
		self.header   = None
		self.ipv4s    = []
		self.ipv6s    = []
		self.segments = []

		if raw_data is not None:
			self.parse_raw_data(raw_data)

	def parse_raw_data(self, data):
		# parse the header
		self.header = ConnectionDataHeader( data[0:ConnectionDataHeader.CONST_SIZE] )
		# validate total size
		num_ipv4 = self.header.ipv4_num_entries()
		num_ipv6 = self.header.ipv6_num_entries()
		num_segments = num_ipv4 + num_ipv6
		expected_size = ConnectionDataHeader.CONST_SIZE + \
						4 * num_ipv4 + \
						16 * num_ipv6 + \
						ConnectionDataSegment.CONST_SIZE * num_segments
		
		data_size = len(data)
		if expected_size != data_size:
			raise Exception('expected ConnectionData of size %d, got %d' % ( 
				expected_size,
				data_size))

		if self.header._cfields['data_size'] != data_size:
			raise Exception('expected ConnectionData.header.size of %d, got %d' % ( 
				data_size,
				self.header._cfields['data_size']))

		# parse ipv4 entries
		offset = ConnectionDataHeader.CONST_SIZE
		for i in range(0, num_ipv4):
			# ipv4 are reversed
			ipv4 = inet_ntop( AF_INET, bytes(reversed(data[offset: offset + 4])) ) 
			self.ipv4s.append(ipv4)
			offset += 4
		
		# parse ipv6 entries
		for i in range(0, num_ipv6):
			ipv6 = inet_ntop( AF_INET6, data[offset: offset + 16] )
			self.ipv6s.append(ipv6)
			offset += 16

		# parse each segment
		for _ in range(0, num_segments):
			segment = ConnectionDataSegment( data[offset: offset +  ConnectionDataSegment.CONST_SIZE] )
			self.segments.append(segment)
			offset += ConnectionDataSegment.CONST_SIZE

	def to_raw_data(self) -> bytes:
		raw = list(self.header.to_raw_data())

		for ipv4 in self.ipv4s:
			raw += list(reversed(list(map(int, ipv4.split('.')))))

		for ipv6 in self.ipv6s:
			raw += list(inet_pton(AF_INET6, ipv6))

		for segment in self.segments:
			raw += list(segment.to_raw_data())

		return bytes(raw)

	@staticmethod
	def build(ipv4s: Tuple[Tuple[str, int, int]], ipv6s: Tuple[Tuple[str, int, int]]) -> ConnectionData:
		data = ConnectionData()

		data.header = ConnectionDataHeader.build(
			ConnectionDataHeader.ENCRYPTION_NONE,
			ConnectionDataHeader.AUTHENTICATION_DISABLED,
			len(ipv4s),
			len(ipv6s)
		)

		for i, ipv4_data in enumerate(ipv4s):
			( ipv4, port, participant_id ) = ipv4_data
			data.ipv4s.append(ipv4)
			data.segments.append(ConnectionDataSegment.build(
				participant_id,
				ConnectionDataSegment.IFACE_TYPE_IPV4,
				i,
				port
			))

		for i, ipv6_data in enumerate(ipv6s):
			( ipv6, port, participant_id ) = ipv6_data
			data.ipv6s.append(ipv6)
			data.segments.append(ConnectionDataSegment.build(
				participant_id,
				ConnectionDataSegment.IFACE_TYPE_IPV6,
				i,
				port
			))

		return data

	def each_ip_port(self):
		for s in self.segments:
			address = self.ipv4s[s.iface_index()] if s.iface_type() == 'IPv4' else self.ipv6s[s.iface_index()]
			port = s._cfields['port']
			yield (address, port)

	def print(self):
		print("  @connection_data")
		self.header.print()

		print("    @addresses")
		for s in self.segments:
			address = self.ipv4s[s.iface_index()] if s.iface_type() == 'IPv4' else self.ipv6s[s.iface_index()]
			print("      ip:port (participant_id) : %s:%d (0x%x)" % (address, s._cfields['port'], s._cfields['participant_id']))
		"""
		print()
		for s in self.segments:
			s.print()
		"""

# Sent from the server as a response the Invite message.
class InviteResponse(object):
	SIGNATURE = 0x0834
	PAYLOAD_SIGNATURE = b'bplist00'

	@staticmethod
	def from_raw_data(data : bytes) -> InviteResponse:
		header = Header()
		header.parse_raw_data(data)
		
		# validate expected signature
		if header.signature != InviteResponse.SIGNATURE:
			raise Exception('expected InviteResponse header signature 0x%x, got 0x%x' % (InviteResponse.SIGNATURE, header.signature))
		# validate payload size
		if header.payload_size == 0:
			raise Exception('expected payload for InviteResponse message, but payload_size is 0')

		# parse bplist into a dictionary
		payload = data[header._csize:]
		if len(payload) != header.payload_size:
			raise Exception('could not read InviteResponse payload of size %d, got %d bytes' % (header.payload_size, len(payload)))
		# check it's a bplist
		if not payload.startswith(InviteResponse.PAYLOAD_SIGNATURE):
			raise Exception('invalid InviteResponse signature, expected %s, got %s' % (
				InviteResponse.PAYLOAD_SIGNATURE,
				hexdump(payload, result='return')
			))
		# parse bplist into a dictionary
		as_dict = plistlib.loads(payload, fmt=plistlib.FMT_BINARY)
		# done
		return InviteResponse(header, as_dict)

	# while we wait for this response, we might receive an Ack (an Header with no payload)
	# or the actual header of this response, this happens in a wait loop so the header
	# has already been read from the socket and is used to determine the size of the
	# bplist payload for the body of this object
	@staticmethod
	def from_reader(header: Header, reader : socket) -> InviteResponse:
		# validate expected signature
		if header.signature != InviteResponse.SIGNATURE:
			raise Exception('expected InviteResponse header signature 0x%x, got 0x%x' % (InviteResponse.SIGNATURE, header.signature))
		# validate payload size
		if header.payload_size == 0:
			raise Exception('expected payload for InviteResponse message, but payload_size is 0')
		# read the payload
		payload = reader.recv(header.payload_size)
		if len(payload) != header.payload_size:
			raise Exception('could not read InviteResponse payload of size %d, got %d bytes' % (header.payload_size, len(payload)))
		# check it's a bplist
		if not payload.startswith(InviteResponse.PAYLOAD_SIGNATURE):
			raise Exception('invalid InviteResponse signature, expected %s, got %s' % (
				InviteResponse.PAYLOAD_SIGNATURE,
				hexdump(payload, result='return')
			))
		# parse bplist into a dictionary
		as_dict = plistlib.loads(payload, fmt=plistlib.FMT_BINARY)
		# done
		return InviteResponse(header, as_dict)

	def __init__(self, header : Header, as_dict : dict):
		self.header = header
		# it should match Invite.data.invite_id
		self.invite_id = as_dict['MCNearbyServiceInviteIDKey']
		# a sequence number, it should be Invite.data.message_id + 1
		self.message_id = as_dict['MCNearbyServiceMessageIDKey']		
		# true or false
		self.accepted = as_dict['MCNearbyServiceAcceptInviteKey']
		# peer identifiers, again ... 
		self.recipient_id = PeerID.from_bplist_encoding(as_dict['MCNearbyServiceRecipientPeerIDKey'])
		self.sender_id = PeerID.from_bplist_encoding(as_dict['MCNearbyServiceSenderPeerIDKey'])
		# only sent if the invitation has been accepted
		self.connection_data_raw = as_dict.get('MCNearbyServiceConnectionDataKey', None)
		# parse connection data if available
		self.connection_data = ConnectionData(self.connection_data_raw) if self.connection_data_raw is not None else None

	def fix_checksum(self) -> None:
		self.header._cfields['crc32'] = 0x00
		without_crc = self.to_raw_data()
		self.header._cfields['crc32'] = zlib.crc32(without_crc)

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + self.to_binary_plist()

	def to_dict(self) -> dict:
		return {
			'MCNearbyServiceInviteIDKey': self.invite_id,
			'MCNearbyServiceMessageIDKey': self.message_id,
			'MCNearbyServiceRecipientPeerIDKey': self.recipient_id.to_bplist_encoding(),
			'MCNearbyServiceSenderPeerIDKey': self.sender_id.to_bplist_encoding(),
			'MCNearbyServiceConnectionDataKey': self.connection_data_raw,
			'MCNearbyServiceAcceptInviteKey': self.accepted,
		}

	def to_binary_plist(self) -> bytes:
		return plistlib.dumps(self.to_dict(), fmt = plistlib.FMT_BINARY)

	def print(self) -> None:
		print("@invite.response")
		self.header.print()
		print("  invite_id : %d" % self.invite_id)
		print("  message_id : %d" % self.message_id)
		if self.accepted is not None:
			print("  accepted : %s" % self.accepted)
		print("  sender_id : %s" % self.sender_id.display())
		print("  recipient_id : %s" % self.recipient_id.display())
		if self.connection_data is not None:
			self.connection_data.print()

# Sent from the client as the last message of the invite sequence.
# Same as InviteResponse but with different client data payload and no accept field.
class InviteClientData(InviteResponse):
	@staticmethod
	def from_raw_data(data : bytes) -> InviteClientData:
		header = Header()
		header.parse_raw_data(data)
		
		# validate expected signature
		if header.signature != InviteClientData.SIGNATURE:
			raise Exception('expected InviteClientData header signature 0x%x, got 0x%x' % (InviteClientData.SIGNATURE, header.signature))
		# validate payload size
		if header.payload_size == 0:
			raise Exception('expected payload for InviteClientData message, but payload_size is 0')

		# parse bplist into a dictionary
		payload = data[header._csize:]
		if len(payload) != header.payload_size:
			raise Exception('could not read InviteClientData payload of size %d, got %d bytes' % (header.payload_size, len(payload)))
		# check it's a bplist
		if not payload.startswith(InviteClientData.PAYLOAD_SIGNATURE):
			raise Exception('invalid InviteClientData signature, expected %s, got %s' % (
				InviteClientData.PAYLOAD_SIGNATURE,
				hexdump(payload, result='return')
			))
		# parse bplist into a dictionary
		as_dict = plistlib.loads(payload, fmt=plistlib.FMT_BINARY)
		# done
		return InviteClientData(header, as_dict)

	@staticmethod
	def from_server_response(server_response: InviteResponse, ipv4s: list, ipv6s: list) -> InviteClientData:
		# create client connection data
		# use the server peer_id, masked with 0x80000000 if it exceeds 32bit representation
		participant_id = server_response.sender_id.identifier_as_32bit() #- 0x80000000
		if participant_id >= 1<<31:
			participant_id -= 0x80000000

		ipv4s_with_id = []
		for (addr, port) in ipv4s:
			ipv4s_with_id.append((addr, port, participant_id))
		
		ipv6s_with_id = []
		for (addr, port) in ipv6s:
			ipv6s_with_id.append((addr, port, participant_id))

		# build client connection data
		conn_data = ConnectionData.build(tuple(ipv4s_with_id), tuple(ipv6s_with_id))
		# create client response dictionary
		as_dict = {
			'MCNearbyServiceInviteIDKey': server_response.invite_id,
			# server.InviteResponse.message_id + 1
			'MCNearbyServiceMessageIDKey': server_response.message_id + 1, 
			# opposite direction
			'MCNearbyServiceRecipientPeerIDKey': server_response.sender_id.to_bplist_encoding(), 
			'MCNearbyServiceSenderPeerIDKey': server_response.recipient_id.to_bplist_encoding(),
			# raw client connection data
			'MCNearbyServiceConnectionDataKey': conn_data.to_raw_data()
		}
		# get header copy
		header = server_response.header
		# create object
		client_data = InviteClientData(header, as_dict)
		# get bplist
		bplist = client_data.to_binary_plist()
		# set new payload length
		client_data.header._cfields['payload_size'] = len(bplist)
		# fix checksum
		client_data.fix_checksum()
		# done
		return client_data

	def __init__(self, header : Header, as_dict : dict):
		self.header = header
		# it should match Invite.data.invite_id
		self.invite_id = as_dict['MCNearbyServiceInviteIDKey']
		# a sequence number, it should be Invite.data.message_id + 1
		self.message_id = as_dict['MCNearbyServiceMessageIDKey']
		# peer identifiers, opposite direction of InviteResponse
		self.recipient_id = PeerID.from_bplist_encoding(as_dict['MCNearbyServiceRecipientPeerIDKey'])
		self.sender_id = PeerID.from_bplist_encoding(as_dict['MCNearbyServiceSenderPeerIDKey'])
		# client connection data
		self.connection_data_raw = as_dict['MCNearbyServiceConnectionDataKey']
		# parse client connection data
		self.connection_data = ConnectionData(self.connection_data_raw)

	def to_dict(self) -> dict:
		return {
			'MCNearbyServiceInviteIDKey': self.invite_id,
			'MCNearbyServiceMessageIDKey': self.message_id,
			'MCNearbyServiceRecipientPeerIDKey': self.recipient_id.to_bplist_encoding(),
			'MCNearbyServiceSenderPeerIDKey': self.sender_id.to_bplist_encoding(),
			'MCNearbyServiceConnectionDataKey': self.connection_data_raw,
		}

	def print(self) -> None:
		print("@invite.client_data")
		self.header.print()
		print("  invite_id : %d" % self.invite_id)
		print("  message_id : %d" % self.message_id)
		print("  sender_id : %s" % self.sender_id.display())
		print("  recipient_id : %s" % self.recipient_id.display())
		self.connection_data.print()			