from __future__ import annotations
from typing import Tuple
import random
import struct
import socket

from mpc.utils import Struct

# STUN (RFC 8489)
MAGIC_COOKIE = 0x2112a442
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-stun.c#L147
# https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
USERNAME_ATTRIBUTE = 0x0006
ICE_CONTROLLED_ATTRIBUTE = 0x8029
ICE_CONTROLLING_ATTRIBUTE = 0x802a
MAPPED_ADDRESS_ATTRIBUTE = 0x0001
USE_CANDIDATE_ATTRIBUTE = 0x0025

ADDRESS_ERROR_CODE_ATTRIBUTE = 0x8001
ALT_DOMAIN_ATTRIBUTE = 0x8003
APPLE_NTP_DELAY_ATTRIBUTE = 0x8004 # this is normally an ICMP attribute, reversed from ICE.framework
APPLE_ATTRIBUTE_8005 = 0x8005
APPLE_ATTRIBUTE_8008 = 0x8008
APPLE_ATTRIBUTE_8009 = 0x8009

ATTRIBUTES = {
	MAPPED_ADDRESS_ATTRIBUTE: "MAPPED-ADDRESS",
	USERNAME_ATTRIBUTE: "USERNAME",
	0x0008: "MESSAGE-INTEGRITY",
	0x0009: "ERROR-CODE",
	0x000A: "UNKNOWN-ATTRIBUTES",
	0x0014: "REALM",
	0x0015: "NONCE",
	0x0020: "XOR-MAPPED-ADDRESS",
	0x0024: "PRIORITY",
	USE_CANDIDATE_ATTRIBUTE: "USE-CANDIDATE",
	ADDRESS_ERROR_CODE_ATTRIBUTE: "ADDRESS-ERROR-CODE",
	ALT_DOMAIN_ATTRIBUTE: "ALTERNATE-DOMAIN",
	APPLE_NTP_DELAY_ATTRIBUTE: "APPLE-NTP-DELAY",
	APPLE_ATTRIBUTE_8005: "APPLE-ATTRIBUTE-8005",
	APPLE_ATTRIBUTE_8008: "APPLE-ATTRIBUTE-8008",
	APPLE_ATTRIBUTE_8009: "APPLE-ATTRIBUTE-8009",
	0x8022: "SOFTWARE",
	0x8023: "ALTERNATE-SERVER",
	0x8028: "FINGERPRINT",
	ICE_CONTROLLED_ATTRIBUTE: "ICE-CONTROLLED",
	ICE_CONTROLLING_ATTRIBUTE: "ICE-CONTROLLING",
	0xc057: "GOOG-NETWORK-INFO"
}

REQUEST_CLASS = 0b00
INDICATION_CLASS = 0b01
SUCCESS_RESPONSE_CLASS = 0b10
ERROR_RESPONSE_CLASS = 0b11

CLASSES = {
	REQUEST_CLASS: "REQUEST",
	INDICATION_CLASS: "INDICATION",
	SUCCESS_RESPONSE_CLASS: "SUCCESS RESPONSE",
	ERROR_RESPONSE_CLASS: "ERROR RESPONSE"
}

BINDING_METHOD = 0b000000000001

METHODS = {
	BINDING_METHOD: "BINDING"
}

class Header(Struct):
	CONST_SIZE = 20

	def __init__(self, data : bytes):
		super(Header, self).__init__(
			'stun.header',
			(
				( 'type', 'H' ), 
				( 'size', 'H' ), 
				( 'cookie', 'I' ), 
				( 'transaction_id', '12s' )
			))
		self.parse_raw_data(data)

		if self._cfields['cookie'] != MAGIC_COOKIE:
			raise Exception("not a STUN packet")

	def attributes_payload_size(self) -> int:
		return self._cfields['size']

class Attribute(Struct):
	MIN_SIZE = 4

	@staticmethod
	def build(type: int, size: int, data: bytes) -> Attribute:
		return Attribute(
			bytes(
				list(type.to_bytes(2, 'big')) + 
				list(size.to_bytes(2, 'big')) +
				list(data)
			)
		)

	def __init__(self, data : bytes):
		super(Attribute, self).__init__(
			'attribute.header',
			(
				( 'type', 'H' ), 
				( 'size', 'H' ), 
			))
		self.data = None
		self.parse_raw_data(data)
		sz = self.size()
		if sz > 0:
			self.data = data[self._csize:self._csize + sz]
		else:
			self.data = b''

	def type(self) -> int:
		return self._cfields['type']

	def size(self) -> int:
		return self._cfields['size']

	def to_raw_data(self) -> bytes:
		return super().to_raw_data() + self.data

	def print(self) -> None:
		print("  <%s>" % ATTRIBUTES.get(self._cfields['type'], '???'))
		print("    type: 0x%x" % self._cfields['type'])
		print("    size: %d" % self._cfields['size'])

		if self.type() == MAPPED_ADDRESS_ATTRIBUTE:
			print("      reserved: 0x%x" % self.data[0])
			print("      protocol: 0x%x" % self.data[1])
			print("      port: %d" % struct.unpack('>H', self.data[2:4]))
			# FIXME: assumes IPv4
			print("      address: %d.%d.%d.%d" % (
				self.data[4], self.data[5], self.data[6], self.data[7]
			))
		elif self.type() == APPLE_NTP_DELAY_ATTRIBUTE:
			print("      delay: %d" % struct.unpack('>I', self.data))
		elif self.type() == USERNAME_ATTRIBUTE:
			print("      sender: 0x%s" % self.data[:10].hex())
			print("      recver: 0x%s" % self.data[10:].hex())
		elif len(self.data) > 0:
			print("    data: %s" % self.data.hex())

class Message(object):
	@staticmethod
	def build(header: Header, attributes: list) -> Message:
		# serialize attributes
		attrs_raw = []
		for attribute in attributes:
			attrs_raw += attribute.to_raw_data()

		# update header 
		header._cfields['size'] = len(attrs_raw) 

		# combine and parse into object
		return Message( bytes(
				list(header.to_raw_data()) + # header
				attrs_raw # attributes payload
			)
		)		
	
	@staticmethod
	def from_udp_socket(sock: socket) -> Tuple[Tuple[str, int], Message]:
		raw, address = sock.recvfrom(1024)
		return (
			address,
			Message(raw)
		)

	def __init__(self, data: bytes):
		self.header = Header(data[0:Header.CONST_SIZE])
		self.parse_class_method()
		self.attributes = []

		data = data[Header.CONST_SIZE:]
		while len(data) >= Attribute.MIN_SIZE:
			attr = Attribute(data)
			self.attributes.append(attr)
			data = data[4 + attr.size():]

	def parse_class_method(self):
		self.type_class = ((self.header._cfields['type'] & 0x0010) >> 4) | ((self.header._cfields['type'] & 0x0100) >> 7)
		self.type_method = (self.header._cfields['type'] & 0x000F) | ((self.header._cfields['type'] & 0x00E0) >> 1) | ((self.header._cfields['type'] & 0x3E00) >> 2)

	def is_binding_request(self) -> bool:
		return self.type_class == REQUEST_CLASS and self.type_method == BINDING_METHOD

	def is_binding_success_response(self) -> bool:
		return self.type_class == SUCCESS_RESPONSE_CLASS and self.type_method == BINDING_METHOD

	def is_binding_response(self) -> bool:
		return self.type_class in (SUCCESS_RESPONSE_CLASS, ERROR_RESPONSE_CLASS) and self.type_method == BINDING_METHOD

	def is_binding_response_to(self, request: Message) -> bool:
		return request.is_binding_request() and \
				self.is_binding_response() and \
				self.header._cfields['transaction_id'] == request.header._cfields['transaction_id']

	def is_successfull_binding_response_to(self, request: Message) -> bool:
		return request.is_binding_request() and \
				self.is_binding_success_response() and \
				self.header._cfields['transaction_id'] == request.header._cfields['transaction_id']


	def get_attribute_by_type(self, type: int) -> Attribute:
		for attr in self.attributes:
			if attr.type() == type:
				return attr
		return None
	
	def get_tie_breaker(self):
		for type in (ICE_CONTROLLING_ATTRIBUTE, ICE_CONTROLLED_ATTRIBUTE):
			attr = self.get_attribute_by_type(type)
			if attr is not None:
				return attr.data

	def to_raw_data(self) -> bytes:
		attrs_raw = []
		for attr in self.attributes:
			attrs_raw += list(attr.to_raw_data())

		return bytes(list(self.header.to_raw_data()) + list(attrs_raw))

	def print(self, full = False) -> None:
		print("STUN.%s.%s" % (
			METHODS.get(self.type_method, '?'),
			CLASSES.get(self.type_class, '?'),
		))
		if full:
			self.header.print()
			for attr in self.attributes:
				attr.print()

# https://www.rfc-editor.org/rfc/rfc5245#section-7.1.2.2
def random_tie_breaker_bytes(endianess = 'big') -> str:
	numeric = random.randint(0, (2**64) - 1) 
	return numeric.to_bytes(8, endianess)

def random_transaction_id_bytes(endianess = 'big') -> str:
	numeric = random.randint(0, (2**64) - 1) 
	return numeric.to_bytes(12, endianess)

def random_icmp_bytes(endianess = 'big') -> str:
	numeric = random.randint(0, (2**16) - 1) 
	return numeric.to_bytes(2, endianess)

def binding_request_from(request: Message, extra_attributes = None, tie_breaker = None) -> Message:
	if not request.is_binding_request():
		raise Exception('not a binding request')

	# build attributes list
	tie_breaker = random_tie_breaker_bytes() if tie_breaker is None else tie_breaker
	ntp_delay = 2043889187

	req_user = request.get_attribute_by_type(USERNAME_ATTRIBUTE)
	attributes = [
		Attribute.build( USERNAME_ATTRIBUTE, 
			req_user._cfields['size'], 
			# swap the 10 bytes words of the request data
			list(req_user.data[10:]) + list(req_user.data[:10])
		),
		Attribute.build( ADDRESS_ERROR_CODE_ATTRIBUTE,
			4,
			[0, 0, 0, 6]
		),
		Attribute.build( ALT_DOMAIN_ATTRIBUTE,
			4,
			[0, 0, 0x03, 0xf2]
		),
		Attribute.build( APPLE_NTP_DELAY_ATTRIBUTE,
			4,
			ntp_delay.to_bytes(4, 'big')
		),
		Attribute.build( ICE_CONTROLLING_ATTRIBUTE,
			8,
			tie_breaker
		)
	]

	if extra_attributes is not None:
		attributes += extra_attributes

	# create header
	req_header = Header( request.header.to_raw_data() ) # same type
	req_header._cfields['transaction_id'] = random_transaction_id_bytes()

	# combine and parse into object
	return Message.build(req_header, attributes)

def binding_response_for(request: Message, ip: str, port: int) -> Message:
	if not request.is_binding_request():
		raise Exception('not a binding request')

	# build attributes list
	req_user = request.get_attribute_by_type(USERNAME_ATTRIBUTE)
	attributes = [
		Attribute.build( USERNAME_ATTRIBUTE, 
			req_user._cfields['size'], 
			# swap the 10 bytes words of the request data
			bytes(list(req_user.data[10:]) + list(req_user.data[:10])) 
		),
		Attribute.build( MAPPED_ADDRESS_ATTRIBUTE, 
			8, 
			[0x00] + # reserved
			[0x01] + # protocol family (IPv4)
			list(port.to_bytes(2, 'big')) + # port
			list(map(int, ip.split('.'))) # ip octects
		),
		Attribute.build( ADDRESS_ERROR_CODE_ATTRIBUTE,
			4,
			[0, 0, 0, 6]
		),
		Attribute.build( ALT_DOMAIN_ATTRIBUTE,
			4,
			[0, 0, 0x03, 0xf2]
		),
		request.get_attribute_by_type(APPLE_NTP_DELAY_ATTRIBUTE),
		Attribute.build( APPLE_ATTRIBUTE_8005, 4, 
			[0x00, 0x00, 0x00, 0x06] # just 6
		)
	]

	# create header
	res_header = Header(request.header.to_raw_data()) # same request transaction id
	res_header._cfields['type'] = 0x0101 # binding success response

	# combine and parse into object
	return Message.build(res_header, attributes)



