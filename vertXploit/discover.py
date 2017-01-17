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
import nmap

from __future__ import print_function
from __future__ import unicode_literals

from main import VertXController


class Discover(VertXController):
	"""
	Send discover request to local broadcast network or scan IP range for VertX controllers.
	"""
	def broadcast(self):
		controllers = []

		response = self.send_command(self.DISCOVER, ip=self.ip)
		if response:
			controllers.append([response[1][0], '4070', response[0].split(';')[2]])

		return controllers

	def scan(self):
		controllers = []

		nm = nmap.PortScanner()
		nm.scan(self.ip, arguments='-n -sS -T2 --open -Pn -p4050')
		for host in nm.all_hosts():
			if nm[host].has_tcp(4050) and nm[host]['tcp'][4050]['state'] == 'open':
				nmap_ip = nm[host]['addresses']['ipv4']
				response = self.send_command(self.DISCOVER, ip=nmap_ip)
				if response:
					controllers.append([response[1][0], '4050', response[0].split(';')[2]])

		return controllers
