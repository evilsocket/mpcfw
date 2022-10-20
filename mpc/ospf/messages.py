from __future__ import annotations

import socket
import json

import plistlib
from crccheck.crc import Crc16Arc

from mpc.utils import Struct

class Header(Struct):
	SIGNATURE = 0xc1
	CONST_SIZE = 16

	@staticmethod
	def from_socket(sock: socket) -> Hello:
		data, _ = sock.recvfrom(Header.CONST_SIZE)
		return Header(data)

	@staticmethod
	def build(type: int, size: int, channel: int, from_id: int, to_id: int) -> Header:
		header = Header(None)
		header._cfields['signature'] = Header.SIGNATURE
		header._cfields['type'] = type
		header._cfields['size'] = size
		header._cfields['channel'] = channel
		header._cfields['crc16'] = 0x0000 # for now, update later with the payload
		header._cfields['from_id'] = from_id
		header._cfields['to_id'] = to_id
		return header

	def __init__(self, data : bytes = None):
		super(Header, self).__init__(
			'ospf.header',
			(
				( 'signature', 'B' ), 
				( 'type',    'B' ), 
				( 'size',    'H' ), 
				( 'channel', 'H' ),
				( 'crc16',   'H' ),
				( 'from_id', 'I' ),
				( 'to_id',   'I' ),
			))
	
		if data is not None:
			self.parse_raw_data(data)
			if self.signature != Header.SIGNATURE:
				raise Exception("not an OSPF packet signature: 0x%x" % self.signature)
	
	def print(self) -> None:
		print("  @header")
		super().print()

class Hello(Struct):
	TYPE       = 0x01
	CONST_SIZE = 34 # Header.CONST_SIZE + 18

	@staticmethod
	def from_socket(sock: socket) -> Hello:
		data, _ = sock.recvfrom(Hello.CONST_SIZE)
		header = Header( data[:Header.CONST_SIZE])
		return Hello(header, data[Header.CONST_SIZE:])

	@staticmethod
	def build(channel: int, from_id: int, to_id: int) -> Hello:
		header = Header.build( Hello.TYPE, Hello.CONST_SIZE, channel, from_id, to_id)

		hello = Hello(header, None)
		hello._cfields['unk_1'] = bytes([0x05, 0x46, 0xf8, 0x01, 0x00, 0x10, 0x0b, 0x02, 0x00, 0x00]) # as seen on wireshark
		hello._cfields['flags'] = 0x800000000000000 # as per logs

		raw = hello.to_raw_data()
		# thanks to https://crccalc.com/ for allowing me to find the crc16 specific type :D
		# fix checksum
		hello.header._cfields['crc16'] = Crc16Arc.calc(raw) 
		
		return hello

	def __init__(self, header: Header, data : bytes):
		super(Hello, self).__init__(
			'ospf.hello',
			(
				( 'unk_1', '10s'),
				( 'flags', 'Q' )
			))

		if header._cfields['type'] != Hello.TYPE:
			raise Exception("not an OSPF Hello packet type: 0x%x" % header._cfields['type'])

		self.header = header

		if data is not None:
			self.parse_raw_data(data)
	
	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + super().to_raw_data()

	def print(self, full=True) -> None:
		print("@OSPF.hello")
		self.header.print()
		print("  @body")
		super().print()

class DD(Struct):		
	TYPE       = 0x02
	CONST_SIZE = 43 # Header.CONST_SIZE + 27

	@staticmethod
	def from_socket(sock: socket) -> DD:
		data, _ = sock.recvfrom(DD.CONST_SIZE)
		return DD.from_raw_data(data)

	@staticmethod
	def from_raw_data(data: bytes) -> DD:
		header = Header( data[:Header.CONST_SIZE])
		return DD(header, data[Header.CONST_SIZE:])

	@staticmethod
	def build(from_id: int, to_id: int, sep_1: bytes, sep_2: bytes, sep_3: bytes, sep_4: bytes, unk_1: int) -> DD:
		header = Header.build( DD.TYPE, DD.CONST_SIZE, 0x00, from_id, to_id)

		dd = DD(header, None)

		dd._cfields['sep_1'] = sep_1
		dd._cfields['from_id'] = from_id
		dd._cfields['sep_2'] = sep_2
		dd._cfields['from_id_str_len'] = 0x08
		dd._cfields['from_id_str'] = from_id.to_bytes(4, 'big').hex().upper().encode('ascii')
		dd._cfields['sep_3'] = sep_3
		dd._cfields['to_id'] = to_id
		dd._cfields['sep_4'] = sep_4
		dd._cfields['unk_1'] = unk_1

		dd.header._cfields['crc16'] = Crc16Arc.calc(dd.to_raw_data()) 
		
		return dd

	@staticmethod
	def build_from_server_dd(srv_dd: DD) -> DD:
		return DD.build(
			srv_dd.to_id,
			srv_dd.from_id,
			srv_dd.sep_1,
			srv_dd.sep_2,
			srv_dd.sep_3,
			srv_dd.sep_4,
			srv_dd.unk_1,
		)

	def __init__(self, header: Header, data : bytes):
		super(DD, self).__init__(
			'ospf.dd',
			(
				( 'sep_1',   		 'H'),  # 00 01
				( 'from_id', 		 'I'), 
				( 'sep_2',   		 'H'),  # 00 01
				( 'from_id_str_len', 'B'),  # 08
				( 'from_id_str', 	 '8s'), # from_id as uppercase string
				( 'sep_3',   		 'H'),  # 00 01
				( 'to_id',  		 'I'),  
				( 'sep_4',   		 'H'),  # 00 00
				( 'unk_1',   		 'H'),  # seems constant
			))

		if header._cfields['type'] != DD.TYPE:
			raise Exception("not an OSPF DD packet type: 0x%x" % header._cfields['type'])

		self.header = header

		if data is not None:
			self.parse_raw_data(data)
	
	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + super().to_raw_data()

	def print(self, full=True) -> None:
		print("@OSPF.DD")
		self.header.print()
		print("  @body")
		super().print()

class Data(Struct):
	TYPE = 0x05

"""
client.ospf.Data.protocolVersion (104 bytes)

	c1 # signature
	05 # type
	00 68 # size (header + payload)
	00 00 # channel unused
	f0 ae # crc16
	70 94 00 bd # from_id
	05 72 44 fb # to_id
	
	[05 00] db 61 # some type on protocolVersion?
	bd 00 94 70 # from_id rev
	fb 44 72 05 # to_id rev
	00 00 # sequence number rev
	00 00 # ?
	
	[02 00] 00 04 01 # protocolVersion type?

	# bplist00 ... {'/protocolVersion': 9}
	62706c6973743030d101025f10102f70726f746f636f6c56657273696f6e1009080b1e0000000000000101000000000000000300000000000000000000000000000020
"""
class ProtocolVersion(Struct):
	CONST_SIZE = 21

	def __init__(self):
		super(ProtocolVersion, self).__init__(
			'ospf.data.protocolVersion',
			(
				( 'protocol_version_specific_1', 'I' ), # 50 00 db 61
				( 'from_id_rev', '4s' ),
				( 'to_id_rev',   '4s' ),
				( 'seq_number_rev', 'I' ),
				( 'protocol_version_specific_2', '5s' ), # 02 00 00 04 01
			))

		self.header = None
		self.as_dict = { '/protocolVersion': 9}
		self.as_bplist = plistlib.dumps(self.as_dict, fmt = plistlib.FMT_BINARY)

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + super().to_raw_data() + self.as_bplist

	def print(self, full=True) -> None:
		print("@OSPF.Data.protocolVersion")
		self.header.print()
		print("  @body")
		super().print()
		print(self.as_dict)

	@staticmethod
	def build(from_id: int, to_id: int) -> ProtocolVersion:
		data = ProtocolVersion()

		size = Header.CONST_SIZE + ProtocolVersion.CONST_SIZE + len(data.as_bplist)
		data.header = Header.build( Data.TYPE, size, 0x00, from_id, to_id)

		data._cfields['protocol_version_specific_1'] = 0x5000db61
		data._cfields['from_id_rev'] = from_id.to_bytes(4, 'little')
		data._cfields['to_id_rev'] = to_id.to_bytes(4, 'little')
		data._cfields['seq_number_rev'] = 0x0
		data._cfields['protocol_version_specific_2'] = bytes([0x02, 0x00, 0x00, 0x04, 0x01])

		data.header._cfields['crc16'] = Crc16Arc.calc(data.to_raw_data()) 
		
		return data

"""
	c1 # signature
	05 # type
	00 62 # size
	00 00 # channel unused
	c5 41 # crc16
	70 94 00 bd # from_id
	05 72 44 fb # to_id
	
	[05 00] d3 3d # some type on jsonSupport?
	bd 00 94 70 # from_id rev
	fb 44 72 05 # to_id rev
	01 00 # sequence number rev
	00 00 # ?

	[02 01] 00 08 01 # jsonSupport type?

	# bplist00 ... {'/jsonSupport': 0}
	62706c6973743030d101025c2f6a736f6e537570706f72741000080b18000000000000010100000000000000030000000000000000000000000000001a
"""
class JsonSupport(Struct):
	CONST_SIZE = 21

	def __init__(self):
		super(JsonSupport, self).__init__(
			'ospf.data.jsonSupport',
			(
				( 'json_support_specific_1', 'I' ), # 50 00 d3 3d
				( 'from_id_rev', '4s' ),
				( 'to_id_rev',   '4s' ),
				( 'seq_number_rev', 'I' ),
				( 'json_support_specific_2', '5s' ), # 02 01 00 08 01 
			))

		self.header = None
		self.as_dict = { '/jsonSupport': 0}
		self.as_bplist = plistlib.dumps(self.as_dict, fmt = plistlib.FMT_BINARY)

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + super().to_raw_data() + self.as_bplist

	def print(self, full=True) -> None:
		print("@OSPF.Data.jsonSupport")
		self.header.print()
		print("  @body")
		super().print()
		print(self.as_dict)

	@staticmethod
	def build(from_id: int, to_id: int) -> JsonSupport:
		data = JsonSupport()

		size = Header.CONST_SIZE + JsonSupport.CONST_SIZE + len(data.as_bplist)
		data.header = Header.build( Data.TYPE, size, 0x00, from_id, to_id)

		data._cfields['json_support_specific_1'] = 0x5000d33d
		data._cfields['from_id_rev'] = from_id.to_bytes(4, 'little')
		data._cfields['to_id_rev'] = to_id.to_bytes(4, 'little')
		data._cfields['seq_number_rev'] = 0x0
		data._cfields['json_support_specific_2'] = bytes([0x02, 0x01, 0x00, 0x08, 0x01])

		data.header._cfields['crc16'] = Crc16Arc.calc(data.to_raw_data()) 
		
		return data		

"""
client.ospf.Data.Start (68 bytes)

	c1 # signature
	05 # type
	00 44 # size
	00 00 # chan unused
	f1 8e # crc16
	70 94 00 bd # from_id
	05 72 44 fb # to_id
	
	[05 00] ae 9f # some type?
	bd 00 94 70 # from_id_rev
	fb 44 72 05 # to_id_rev
	0c 00 # sequence
	00 00 # ?
	32 0c # ?
	[00 34] 04
	
	# json (31 bytes) {"\\/cs\\/transport\\/stop":false}
	7b225c2f63735c2f7472616e73706f72745c2f73746f70223a66616c73657d
"""
class StopOrNot(Struct):
	CONST_SIZE = 21

	def __init__(self, stop: bool):
		super(StopOrNot, self).__init__(
			'ospf.data.StopOrNot',
			(
				( 'stop_specific_1', 'I' ), # 50 00 ae 9f
				( 'from_id_rev', '4s' ),
				( 'to_id_rev',   '4s' ),
				( 'seq_number_rev', 'I' ),
				( 'stop_specific_2', '5s' ), # 32 0c 00 34 04
			))

		self.header = None
		self.as_dict = {'\\/cs\\/transport\\/stop': stop}
		self.as_json = json.dumps(self.as_dict).encode('ascii')

	def to_raw_data(self) -> bytes:
		return self.header.to_raw_data() + super().to_raw_data() + self.as_json

	def print(self, full=True) -> None:
		print("@OSPF.Data.stopOrNot")
		self.header.print()
		print("  @body")
		super().print()
		print(self.as_json)

	@staticmethod
	def build(from_id: int, to_id: int, stop: bool) -> StopOrNot:
		data = StopOrNot(stop)

		size = Header.CONST_SIZE + StopOrNot.CONST_SIZE + len(data.as_json)
		data.header = Header.build( Data.TYPE, size, 0x00, from_id, to_id)

		data._cfields['stop_specific_1'] = 0x5000ae9f
		data._cfields['from_id_rev'] = from_id.to_bytes(4, 'little')
		data._cfields['to_id_rev'] = to_id.to_bytes(4, 'little')
		data._cfields['seq_number_rev'] = 0x0
		data._cfields['stop_specific_2'] = bytes([0x32, 0x0c, 0x00, 0x34, 0x04])

		data.header._cfields['crc16'] = Crc16Arc.calc(data.to_raw_data()) 
		
		return data			