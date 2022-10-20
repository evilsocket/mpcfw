# a few tests so i'm sure i'm not breaking basic protocol constraints 
# when i experiment around - run with: python3 -m mpc.messages_tests
if __name__ == '__main__':
	from .messages import *
	
	def test_hello_parsing():
		print("test_hello_parsing")

		payload = [
			0x07, 0xd0, # signature
			0x00, 0x00, 0x00, 0x00, # sometimes it's 0x00, 0x01, 0x00, 0x00
			0x00, 0x1b, # payload length -> 27 (peer_id_len + string_len + data)
			0xd8, 0x5a, 0xfd, 0x5d, # checksum
			0x00, 0x00, 0x00, 0x00, # ?
			# payload starts here
			0x00, 0x00, 0x00, 0x06, # flags
			0x00, 0x15, # total string length -> 21
			0x32, 0x64, 0x39, 0x6f, 0x6d, 0x71, 0x74, 0x6b, 0x7a, 0x31, 0x37, 0x73, 0x74, 0x2b, # 2d9omqtkz17st+
			0x41, 0x6e, 0x74, 0x61, 0x6e, 0x69, 0x00 # 'Antani', null terminated
		]

		hello = Hello.from_raw_data(bytes(payload))
		
		assert( hello.header.signature == Hello.SIGNATURE )
		assert( hello.header.maybe_seqn == 0x00 )
		assert( hello.header.payload_size == 0x1b )
		assert( hello.header.crc32 == 0xd85afd5d )
		assert( hello.header.unk_1 == 0)

		assert( hello.peer_id.flags == 0x06 )
		assert( hello.peer_id.length == 0x15 )
		assert( hello.peer_id.identifier() == '2d9omqtkz17st' )
		assert( hello.peer_id.name() == 'Antani' )
		assert( len(hello.peer_id.peer_string()) == hello.peer_id.length )
		assert( hello.to_raw_data() == bytes(payload) )

		hello.print(True)
		print()

	def test_hello_building():
		print("test_hello_building")

		hello = Hello.build('foo', 'bar')

		hello.print(True)
		print()

		assert( hello.header.signature == Hello.SIGNATURE )
		assert( hello.header.maybe_seqn == 0x00 )
		assert( hello.header.payload_size == 0xe )
		assert( hello.header.crc32 == 0xf7d9b3b7 )
		assert( hello.header.unk_1 == 0)

		assert( hello.peer_id.flags == 0x06 )
		assert( hello.peer_id.length == 8 )
		assert( hello.peer_id.identifier() == 'foo' )
		assert( hello.peer_id.name() == 'bar' )
		assert( len(hello.peer_id.peer_string()) == hello.peer_id.length )

	def test_ack_parsing():
		print("test_ack_parsing")

		payload = [
			0x07, 0xd0, # signature
			0x00, 0x01, 0x00, 0x00, # sequence number?
			0x00, 0x00, # payload_size, set to 0 because Ack has no data
			0x0c, 0xca, 0x7e, 0x2c, # checksum
			0x00, 0x00, 0x00, 0x00  # no idea
		]

		ack = Ack.from_raw_data(bytes(payload))

		assert( ack.header.signature == Ack.SIGNATURE )
		assert( ack.header.maybe_seqn == 0x00010000 )
		assert( ack.header.payload_size == 0 )
		assert( ack.header.crc32 == 0x0cca7e2c )
		assert( ack.header.unk_1 == 0)
		assert( ack.to_raw_data() == bytes(payload) )

		ack.print(True)
		print()

	def test_ack_building():
		print("test_ack_building")
		
		ack = Ack.build(0x00010000)

		assert( ack.header.signature == Ack.SIGNATURE )
		assert( ack.header.maybe_seqn == 0x00010000 )
		assert( ack.header.payload_size == 0 )
		assert( ack.header.crc32 == 0x0cca7e2c )
		assert( ack.header.unk_1 == 0)
		assert( ack.to_raw_data() == bytes([
			0x07, 0xd0, 
			0x00, 0x01, 0x00, 0x00, 
			0x00, 0x00,
			0x0c, 0xca, 0x7e, 0x2c, 
			0x00, 0x00, 0x00, 0x00
		]))

		ack = Ack.build(0x00)

		assert( ack.header.signature == Ack.SIGNATURE )
		assert( ack.header.maybe_seqn == 0x00 )
		assert( ack.header.payload_size == 0 )
		assert( ack.header.crc32 == 0xd15ca7a9 )
		assert( ack.header.unk_1 == 0)
		assert( ack.to_raw_data() == bytes([
			0x07, 0xd0, 
			0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00,
			0xd1, 0x5c, 0xa7, 0xa9, 
			0x00, 0x00, 0x00, 0x00
		]))

		ack.print(True)
		print()

	def test_accept_parsing():
		print("test_accept_parsing")

		payload = [
			0x08, 0x98, # signature
			0x00, 0x00, 0x00, 0x00, # maybe a sequence number
			0x00, 0x00, # no payload, payload_size is 0
			0xb4, 0xca, 0x16, 0x45, # checksum
			0x00, 0x00, 0x00, 0x02 # no idea
		]

		accept = Accept.from_raw_data(bytes(payload))

		assert( accept.header.signature == Accept.SIGNATURE )
		assert( accept.header.maybe_seqn == 0x0 )
		assert( accept.header.payload_size == 0 )
		assert( accept.header.crc32 == 0xb4ca1645 )
		assert( accept.header.unk_1 == 0x2)
		assert( accept.to_raw_data() == bytes(payload) )

		accept.print(True)
		print()

	def test_accept_building():
		print("test_accept_building")
		
		accept = Accept.build(0x0)

		assert( accept.header.signature == Accept.SIGNATURE )
		assert( accept.header.maybe_seqn == 0x00 )
		assert( accept.header.payload_size == 0 )
		assert( accept.header.crc32 == 0x5ac47769 )
		assert( accept.header.unk_1 == 0)
		assert( accept.to_raw_data() == bytes([
			0x08, 0x98,
			0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00,
			0x5a, 0xc4, 0x77, 0x69,
			0x00, 0x00, 0x00, 0x00
		]))

		accept = Accept.build(0x01)

		assert( accept.header.signature == Accept.SIGNATURE )
		assert( accept.header.maybe_seqn == 0x01 )
		assert( accept.header.payload_size == 0 )
		assert( accept.header.crc32 == 0x9b4aa8a9 )
		assert( accept.header.unk_1 == 0)
		assert( accept.to_raw_data() == bytes([
			0x08, 0x98,
			0x00, 0x00, 0x00, 0x01, 
			0x00, 0x00,
			0x9b, 0x4a, 0xa8, 0xa9,
			0x00, 0x00, 0x00, 0x00
		]))

		accept.print(True)
		print()		

	def test_connection_data_parsing():
		print("test_connection_data_parsing")

		# 0x10 = 1 entry   | 0b0001 0000 | 1 0 ( 1 ipv4 + 0 ipv6 )
		# 0x11 = 2 entries | 0b0001 0001 | 1 1 ( 1 ipv4 + 1 ipv6 )
		# 0x22 = 4 entries | 0b0010 0010 | 2 2 ( 2 ipv4 + 2 ipv6 )
		payload = [
			0x80, # packet signature
			0x02, # security (no encryption, no auth)
			0x00, 0x6D, # data size ( 109 )
			0x22, # number of entries ( first 4 bits for n of ipv4, last 4 bits for n of ipv6 )
			
			0x37, 0x01, 0xA8, 0xC0, # ipv4_rev 192.168.1.55
			0x27, 0x01, 0xA8, 0xC0, # ipv4_rev 192.168.1.39
			0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xD5, 0xFC, 0xB6, 0x03, 0x61, 0x8C, 0x04, # ipv6
			0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x35, 0x48, 0x90, 0x9B, 0x2E, 0xC9, # ipv6
			
			0x61, # segment begin
			0xB0, 0x66, 0x31, 0x0A, # client id rev
			0x47, 0xCA, 0x5C, 0x4D, # random id part
			0x0A, # iface type: ipv6
			0x00, 0x00, 0x00, 0x90, # iface index -> 0x9n -> 0x9=ipv6 ( b1001 ) / 0x0=index
			0x11, 0x40, # port rev 16401
			
			0x61, # segment begin
			0xB0, 0x66, 0x31, 0x0A, # client id rev
			0x05, 0xCF, 0x2D, 0x29, # random id part
			0x5A, # iface type: ipv4
			0x00, 0x00, 0x00, 0x80, # iface index -> 0x8n -> 0x8=ipv4 ( b1000 ) / 0x0=index 
			0x12, 0x40, # port rev 16402
			
			0x61, # segment begin
			0xB0, 0x66, 0x31, 0x0A, # client id rev
			0x6E, 0x92, 0x27, 0x07, # random id part
			0x5A, # iface type: ipv4
			0x00, 0x00, 0x00, 0x81, # iface index -> 0x8n -> 0x8=ipv4 ( b1000 ) / 0x1=index 
			0x09, 0x40, # port rev 16393
			
			0x61, # segment begin
			0xB0, 0x66, 0x31, 0x0A, # client id rev
			0x2A, 0x11, 0xFC, 0x84, # random id part
			0x0A, # iface type: ipv6
			0x00, 0x00, 0x00, 0x91, # iface index -> 0x9n -> 0x9=ipv6 ( b1001 ) / 0x1=index
			0x09, 0x40 # port rev 16393
		]

		cdata = ConnectionData(bytes(payload))
		cdata.print()
		print()

		# test header
		assert( cdata.header._cfields['signature'] == ConnectionDataHeader.SIGNATURE )
		assert( cdata.header._cfields['security'] == 0x02 )
		assert( cdata.header._cfields['data_size'] == len(payload) )
		assert( cdata.header._cfields['entries'] == (0x2 | 0x2 << 4) )
		assert( cdata.header.auth_enabled() == False )
		assert( cdata.header.encryption_type() == 'none' )
		# test ips block
		assert( cdata.ipv4s == ['192.168.1.55', '192.168.1.39'])
		assert( cdata.ipv6s == ['fe80::10d5:fcb6:361:8c04', 'fe80::60:3548:909b:2ec9'])
		# test segments
		assert( len(cdata.segments) == 4 )
		for seg in cdata.segments:
			assert( seg._cfields['signature'] == ConnectionDataSegment.SIGNATURE )
			assert( seg._cfields['participant_id'] == 0xa3166b0 )
			assert( seg._cfields['iface_type'] in (ConnectionDataSegment.IFACE_TYPE_IPV4, ConnectionDataSegment.IFACE_TYPE_IPV6) )
			assert( seg.iface_type() in ('IPv4', 'IPv6') )
			assert( seg._cfields['iface_index'] in (0x80, 0x81, 0x90, 0x91))
			assert( seg.iface_index() in (0, 1))
			assert( seg._cfields['port'] in (16393, 16401, 16402))

		# test serialization
		raw2 = cdata.to_raw_data()
		cdata = ConnectionData(bytes(raw2))

		assert( payload == list(raw2) )

	def test_connection_data_building():
		print("test_connection_data_building")

		cdata = ConnectionData.build( 
			(
				( '192.168.1.55', 16402, 0xa3166b0 ),
				( '192.168.1.39', 16393, 0xa3166b0 )
			), 
			(
				( 'fe80::10d5:fcb6:361:8c04', 16401, 0xa3166b0 ),
				( 'fe80::60:3548:909b:2ec9', 16393, 0xa3166b0 )
			)
		)
		cdata.print()

		# test header
		assert( cdata.header._cfields['signature'] == ConnectionDataHeader.SIGNATURE )
		assert( cdata.header._cfields['security'] == 0x02 )
		assert( cdata.header._cfields['data_size'] == 109 )
		assert( cdata.header._cfields['entries'] == (0x2 | 0x2 << 4) )
		assert( cdata.header.auth_enabled() == False )
		assert( cdata.header.encryption_type() == 'none' )
		# test ips block
		assert( cdata.ipv4s == ['192.168.1.55', '192.168.1.39'])
		assert( cdata.ipv6s == ['fe80::10d5:fcb6:361:8c04', 'fe80::60:3548:909b:2ec9'])
		# test segments
		assert( len(cdata.segments) == 4 )
		for seg in cdata.segments:
			assert( seg._cfields['signature'] == ConnectionDataSegment.SIGNATURE )
			assert( seg._cfields['participant_id'] == 0xa3166b0 )
			assert( seg._cfields['iface_type'] in (ConnectionDataSegment.IFACE_TYPE_IPV4, ConnectionDataSegment.IFACE_TYPE_IPV6) )
			assert( seg.iface_type() in ('IPv4', 'IPv6') )
			assert( seg._cfields['iface_index'] in (0x80, 0x81, 0x90, 0x91))
			assert( seg.iface_index() in (0, 1))
			assert( seg._cfields['port'] in (16393, 16401, 16402))

	test_hello_parsing()
	test_hello_building()
	test_ack_parsing()
	test_ack_building()
	test_accept_parsing()
	test_accept_building()
	# TODO: add tests for InviteData
	# TODO: add tests for Invite
	# TODO: add tests for InviteResponse
	test_connection_data_parsing()
	test_connection_data_building()