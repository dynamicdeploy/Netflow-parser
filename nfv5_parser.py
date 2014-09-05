# -*- coding: utf-8 -*-

import sys
import dpkt, socket
import struct
from collections import OrderedDict

nfv5_header_format = OrderedDict([
	('version', 2),
	('count', 2),
	('sys_uptime', 4),
	('unix_secs', 4),
	('unix_nsecs', 4),
	('flow_sequence', 4),
	('engine_type', 1),
	('engine_id', 1),
	('sampling_interval', 2) 
])

nfv5_record_format = OrderedDict([
	('srcaddr', 4),
	('dstaddr', 4),
	('nexthop', 4),
	('input_interface', 2),
	('output_interface', 2),
	('packets', 4),
	('octets', 4),
	('start_time', 4),
	('end_time', 4),
	('src_port', 2),
	('dst_port', 2),
	('pad1', 1),
	('tcp_flags', 1),
	('protocol', 1),
	('tos', 1),
	('src_as', 2),
	('dst_as', 2),
	('src_mask', 1),
	('dst_mask', 1),
	('pad2', 2)
])


class NetflowParserV5:
	def __init__(self):
		self.udp_sessions = []
		self.nf = None
		self.type = {1: '!B', 2: '!H', 4: '!I'}
		self.num_of_header_field = 9

	def parse(self, pcap):
		for timestamp, buf in pcap:
			eth = dpkt.ethernet.Ethernet(buf)
			self.nf = eth.data.data.data
			pkt = []
			base = 0
			# --- parse header -------
			for content, length in nfv5_header_format.iteritems():
				pkt.append(self.retrieve_content(base, length))
				base += length
			# --- parse flow records -------
			frecord_cnt = int(pkt[1])
			for i in range(frecord_cnt):
				pdu = []
				for content, length in nfv5_record_format.iteritems():
					pdu.append(self.retrieve_content(base, length))
					base += length
				pkt.append(pdu)
			self.udp_sessions.append(pkt)

	def retrieve_content(self, base, length):
		return str(struct.unpack(self.type[length], self.nf[base : (base + length)])[0])

	def print_session(self, num):
		frecord_cnt = int(self.udp_sessions[num][1])
		for index, content in enumerate(nfv5_header_format.keys()):
			print content + ': ' + self.udp_sessions[num][index]
		for i in range(frecord_cnt):
			print 'pdu #' + str(i) + ':'
			for index, content in enumerate(nfv5_record_format.keys()):
				val = self.udp_sessions[num][self.num_of_header_field + i][index]
				if 'addr' in content or content == 'nexthop':
					print '\t' + content + ': ' + socket.inet_ntoa(struct.pack('!I', int(val)))
				else:
					print '\t' + content + ': ' + val

	#def write_to_file(self):



if __name__ == '__main__':
	nfv5_parser = NetflowParserV5()
	with open(sys.argv[1], 'r') as f:
		nfv5_parser.parse(dpkt.pcap.Reader(f))
	nfv5_parser.print_session(19)

