#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import dpkt
from dpkt.compat import compat_ord
import json
import socket
import struct
from hashlib import md5

DHCP_PORT = 67
BOOT_REQ = 1


def convert_ip(value):
	"""Convert an IP address from binary to text.
....:param value: Raw binary data to convert
....:type value: str
....:returns: str
...."""

	try:
		return socket.inet_ntop(socket.AF_INET, value)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, value)

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def process_pcap(pcap):
	"""Process packets within the PCAP.
....:param pcap: Opened PCAP file to be processed
....:type pcap: dpkt.pcap.Reader
....:returns: list of parsed records
...."""

	results = list()

	# Iterate through each packet in the pcap

	for (ts, pkt) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(pkt)
		except Exception:
			continue
		if not isinstance(eth.data, dpkt.ip.IP):

			# Only want IP packets

			continue
		macsrc = None
		if eth != None:
			macsrc = mac_addr(eth.src)
			#print(macsrc,eth.src)

		ip = eth.data
		if ip.p != dpkt.ip.IP_PROTO_UDP:

			# Only want UDP packets

			continue

		udp = ip.data
		try:
			if not (udp.sport == DHCP_PORT or udp.dport == DHCP_PORT):

			# Looking for the DHCP Packets

				continue
		except:
			pass
		try:
			if len(udp.data) <= 0:
				continue
		except:
			continue
		bootstrap = bytearray(udp.data)
		if bootstrap[0] != BOOT_REQ:

			# only look for client to server DHCP messages (DHCP Reqs.)

			continue

		dhcp = dpkt.dhcp.DHCP(udp.data)

		int_vals = list()

		# Iterate through the Options list of tuples

		for opt in dhcp.opts:
			if opt[0] == 55:

				# Only look for the Param Req. List

				data = bytearray(opt[1])
				for i in range(0, len(data)):
					element = data[i]
					int_vals.append(element)

		dhcpfp = ','.join(str(x) for x in int_vals)
		record = {
			'source_ip': convert_ip(ip.src),
			'destination_ip': convert_ip(ip.dst),
			'source_port': udp.sport,
			'destination_port': udp.dport,
			'DHCPFP': dhcpfp,
			'DHCPFP_hash': md5(dhcpfp.encode()).hexdigest(),
			'timestamp': ts,
			'source_mac': macsrc,
			}
		results.append(record)
	return results


def main():
	"""Intake arguments from the user and print out kyd hash output."""

	desc = \
		'A python script for extracting DHCP fingerprints from PCAP files'
	parser = argparse.ArgumentParser(description=desc)
	parser.add_argument('pcap', help='The pcap file to process')

	help_text = 'Print out as JSON records for downstream parsing'
	parser.add_argument(
		'-j',
		'--json',
		required=False,
		action='store_true',
		default=True,
		help=help_text,
		)
	args = parser.parse_args()
	filename = args.pcap

	# Use an iterator to process each line of the file

	output = None
	with open(filename, 'rb') as fp:
		try:
			capture = dpkt.pcap.Reader(fp)
		except ValueError as e:
			raise Exception("File doesn't appear to be a PCAP: %s" % e)
		output = process_pcap(capture)

	if args.json:
		output = json.dumps(output, indent=4, sort_keys=True)
		print(output)
	else:
		for record in output:
			tmp = '[{src}:{port}] kyd: {segment} --> {digest} {mac}'
			tmp = tmp.format(src=record['source_ip'],
							 port=record['source_port'],
							 segment=record['DHCPFP'],
							 digest=record['DHCPFP_hash'],
							 mac = record['source_mac'])
			print(tmp)


if __name__ == '__main__':
	main()
