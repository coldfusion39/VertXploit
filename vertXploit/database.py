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
import os

from __future__ import print_function
from __future__ import unicode_literals


class Database(object):
	"""
	Dump card information from VertX databases.
	"""
	def __init__(self, path):
		self.identdb = "{0}/IdentDB".format(os.path.abspath(path))
		self.accessdb = "{0}/AccessDB".format(os.path.abspath(path))

	def dump(self):
		card_data = []

		# Get card information from IdentDB
		block_size = 28
		identdb_data = self.parse_db(self.identdb, block_size)
		for i_entry in identdb_data:
			I_ENTRY_NUMBER = 16
			I_CARD_ID = 10
			I_ENABLED = 24

			database_id = i_entry[(I_ENTRY_NUMBER * 2):(I_ENTRY_NUMBER * 2) + 2]
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
			block_size = 44
			accessdb_data = self.parse_db(self.accessdb, block_size)
			for a_entry in accessdb_data:
				A_ENTRY_NUMBER = 0
				A_DOOR_ACCESS = 8

				accessdb_id = a_entry[A_ENTRY_NUMBER * 2:(A_ENTRY_NUMBER * 2) + 2]
				if accessdb_id == database_id:
					door_access = a_entry[A_DOOR_ACCESS * 2:(A_DOOR_ACCESS * 2) + 2]
					break
				else:
					continue

			database_row = [database_id, card_id, door_access, enabled]
			card_data.append(database_row)

		return card_data

	def parse_db(self, database, block):
		data = []
		counter = 1
		entry = 0

		with open(database, 'rb') as file_stream:
			while entry < 255:
				card_block = file_stream.read(block)
				if card_block:
					if (counter == 1) or (counter % block == 1):
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
