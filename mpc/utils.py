import struct
import zlib
import random
import string
import socket

import base36
from hexdump import hexdump

# Search for a valid checksum in an unknown buffer.
# Not really used anymore, but it's been so useful during the RE process
# that i kept this little function here :D
def find_checksum(data, fn = zlib.crc32, word_size = 4):
	data = bytearray(data)
	data_len = len(data)
	formats = {
		2: 'H',
		4: 'I'
	}
	# check byte by byte with a word_size bytes sliding window
	for offset in range(0, data_len - word_size):
		# get current dword bytes
		dword_bytes = data[offset: offset + word_size]
		dword = struct.unpack('>' + formats[word_size], dword_bytes)[0]
		# zeroize bytes at this position
		data[offset: offset + word_size] = [0] * word_size
		# compute checksum on the whole thing
		crc = fn(data)
		if crc == dword:
			print("found checksum 0x%x at offset %d" % (crc, offset))
			return
		# restore original dword before continuing from the next offset
		data[offset: offset + word_size] = dword_bytes

# generate a random peer_id string for this session
def random_peer_id() -> str:
	numeric = random.randint(0, 4294967296) 
	return base36.dumps(numeric) 

# generate a random peer_name string for this session
def random_peer_name(length : int = 10) -> str:
	return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# get bind information for an ipv6 address
def get_ipv6_bind_address(address, port):
	for ainfo in socket.getaddrinfo(address, port):
		if ainfo[0].name == 'AF_INET6' and ainfo[1].name == 'SOCK_DGRAM':
			return ainfo[4]

# utility object used to unpack values from raw data and pack them back
# given a series of struct.pack/unpack field descriptors and names
class Struct(object):
	def __init__(self, name: str, fmt: tuple, endianess='>'):
		self._cfmt = fmt
		self._cfmt_str = endianess + ''.join([fmt for (_, fmt) in self._cfmt])
		self._csize = struct.calcsize(self._cfmt_str)
		self._cfields = {name: 0x00 for (name, _) in self._cfmt}

	def __getattr__(self, name):
		return self._cfields[name]

	# https://bugs.python.org/issue19364
	def __copy__(self):
		cls = self.__class__
		result = cls.__new__(cls)
		result.__dict__.update(self.__dict__)
		return result

	def parse_raw_data(self, data: bytes) -> None:
		try:
			unpacked = struct.unpack(self._cfmt_str, data[:self._csize])
		except Exception as e:
			print("can't decode data with format '%s':\n\n  %s\n" % (
				self._cfmt_str, 
				hexdump(data, result='return')))
			raise e

		for idx, (field_name, _) in enumerate(self._cfmt):
			self._cfields[field_name] = unpacked[idx]

	def to_raw_data(self) -> bytes:
		values = []
		for (name, _) in self._cfmt:
			values.append(self._cfields[name])
		return struct.pack( self._cfmt_str, *values )
		
	def print(self) -> None:
		for (name, fmt) in self._cfmt:
			data = self._cfields[name]
			if type(data) == bytes:
				print("    %s : %s" % (name, ', '.join(['0x%x' % b for b in data])))
			else:
				zeros = struct.calcsize(fmt) * 2
				print(("    %s : 0x%0" + str(zeros) + "x (%d)") % (name, data, data))        