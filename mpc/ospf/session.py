from hexdump import hexdump

from mpc.ospf.messages import *

# MultipeerConnectivity.framework refers to this session as OSPF, but guess what?
# It is not standard OSPF but some custom made crap named after OSPF ...
def start_session(sock, remote):
	print("[OSPF] starting session with %s" % str(remote))

	# read Hello
	srv_hello = Hello.from_socket(sock)
	print("< server.", end='')
	srv_hello.print()

	# send Hello
	cli_hello = Hello.build(0x03, srv_hello.header.to_id, srv_hello.header.from_id)
	print("> client.", end='')
	cli_hello.print()
	sock.sendto(cli_hello.to_raw_data(), remote)

	# read DD
	srv_dd = DD.from_socket(sock)
	print("< server.", end='')
	srv_dd.print()

	# send DD
	cli_dd = DD.build_from_server_dd(srv_dd)
	print("> client.", end='')
	cli_dd.print()
	sock.sendto(cli_dd.to_raw_data(), remote)

	# read server LSA
	data, rcvd_from = sock.recvfrom(1024)
	
	print("< server (%s):" % str(rcvd_from))
	try:
		header = Header( data[:Header.CONST_SIZE])
		header.print()
	except:
		print("not a valid OSPF header")

	while True:
		data, rcvd_from = sock.recvfrom(1024)
		
		print("< server (%s):" % str(rcvd_from))
		try:
			header = Header( data[:Header.CONST_SIZE])
			header.print()
		except:
			print("not a valid OSPF header")

		hexdump(data)