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
import os.path
from tabulate import tabulate


def main():
	parser = argparse.ArgumentParser(description='Parse HID VertX card data from databases')
	parser.add_argument('-p', dest='path', help='Path to database files', default='./', required=False)
	parser.add_argument('-v', dest='verbose', help='Verbose', action='store_true', required=False)
	args = parser.parse_args()

	# Check if database files exist
	if os.path.isfile("{0}/IdentDB".format(args.path)) and os.path.isfile("{0}/AccessDB".format(args.path)):

		# Pull info from databases
		print_status('Processing card information from VertX database')
		identDB_data = read_db("{0}/IdentDB".format(args.path), args.verbose)
		accessDB_data = read_db("{0}/AccessDB".format(args.path), args.verbose)

		# Parse databases
		parse_db(identDB_data, accessDB_data)
	else:
		print_error("Could not find IdentDB or AccessDB at {0}".format(os.path.abspath(args.path)))


# Read database and return data
def read_db(db, verbose):
	data = []
	data_table = []
	counter = 1
	entry = 0

	with open(db, 'rb') as file_stream:
		if 'IdentDB' in db:
			block_size = 28
			if verbose:
				print_good('IdentDB Data')
		else:
			block_size = 44
			if verbose:
				print_good('AccessDB Data')

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
				if verbose:
					data_row = [entry, card_data]
					data_table.append(data_row)
			else:
				break

	file_stream.close()
	if verbose:
		print(tabulate(data_table, headers=['Entry', 'Card Data'], tablefmt='psql', stralign='center'))

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

		# Get Door access from AccessDB
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
		print(tabulate(card_data, headers=['DB ID', 'Card ID', 'Door', 'Enabled'], tablefmt='psql', stralign='center'))
	else:
		print_warn('Unable to recover cards from database')


def print_error(msg):
	print("\033[1m\033[31m[-]\033[0m {0}".format(msg))


def print_status(msg):
	print "\033[1m\033[34m[*]\033[0m {0}".format(msg)


def print_good(msg):
	print "\033[1m\033[32m[+]\033[0m {0}".format(msg)


def print_warn(msg):
	print "\033[1m\033[33m[!]\033[0m {0}".format(msg)

if __name__ == '__main__':
	main()
