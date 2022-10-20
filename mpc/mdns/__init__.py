from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
import socket
import threading

# simple mDNS based discovery, nothing new, not really interesting

SERVICE_TYPE = '_apple-lgremote._tcp.local.'

HOST_TYPES = {
	b'0': 'logic pro',
	b'1': 'garageband'
}

class Service(object):
	def __init__(self, info):
		self.server = info.server
		self.name = info.name
		self.address = socket.inet_ntoa(info.addresses[0])
		self.port = info.port
		self.type = HOST_TYPES[info.properties[b'/hostType']] if info.properties[b'/hostType'] in HOST_TYPES else 'unknown'

class Listener(ServiceListener):
	def __init__(self):
		super(Listener, self).__init__()
		self.service = None
		self._cond = threading.Condition()

	def _is_mpc_service(self, info):
		return info.type == '_apple-lgremote._tcp.local.' and \
				len(info.addresses) > 0 and \
				info.port != 0 and \
				b'/hostType' in info.properties

	def _found(self, info):
		self.service = Service(info)
		print("found multi peer connectivity service '%s' (%s) [type=%s] on %s:%d" % (
			self.service.server,
			self.service.name,
			self.service.type,
			self.service.address,
			self.service.port
		))
		self._cond.acquire()
		self._cond.notify()
		self._cond.release()

	def wait(self):
		self._cond.acquire()
		self._cond.wait()
		self._cond.release()

	def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
		pass

	def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
		pass

	def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
		info = zc.get_service_info(type_, name)
		if self._is_mpc_service(info):
			self._found(info)

def discover() -> Service:
	print("waiting for mDNS discovery packet ...")
	zeroconf = Zeroconf()
	listener = Listener()
	browser = ServiceBrowser(zeroconf, "_apple-lgremote._tcp.local.", listener)
	listener.wait()
	zeroconf.close()
	return listener.service