#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import requests
import time
import json
import argparse
from collections import defaultdict
import gzip

OUTFNAME = 'dhcp-db-FBQ'

def getallFPlogs(logpath='/usr/local/zeek/logs'):
	""" find all subdirs of log and find all like dhcpfp.15:34:54-16:00:00.log.gz 
		parse these into the required format. Return a dict keyed by hash of dhcp signatures
	"""

	dlist = os.listdir(logpath)
	sigs = []
	for dn in dlist:
		dnpath = os.path.join(logpath, dn)
		if os.path.isdir(dnpath):
			flist = os.listdir(dnpath)
			flist = [x for x in flist if x.startswith('dhcpfp')]
			for fn in flist:
				fnpath = os.path.join(dnpath, fn)
				if fnpath.endswith('log.gz'):
					dat = gzip.open(fnpath, 'rt').readlines()
				else:
					dat = open(fnpath, 'r').readlines()
				dat = [x for x in dat if not x.startswith('#')]
				dats = [x.split()[8:10] for x in dat if x[7].lower() == "unknown"]
				sigs += dats
	return dict(sigs)  # removes dupes


def queryFingerbank(file_dic, key, proxy):
	"""query Fingerbank API for the DHCP FPs provided in file_dic with the API key"""

	headers = {'Content-type': 'application/json'}
	url = \
		'https://api.fingerbank.org/api/v2/combinations/interrogate?key=' \
		+ key

	resp_dic = defaultdict(list)
	if 'https' in proxy:
		proxies = {'https': proxy}
	else:
		proxies = {'http': proxy}
	writeme = []
	nrec = 0
	for (hash, fp) in file_dic.items():
		data = '{"dhcp_fingerprint":"' + fp + '"}'
		resp_dic[hash].append(fp)
		try:

			# Try to get the data and json.load it 3 times, then give up

			tries = 3
			while tries >= 0:
				try:
					newrec = ''
					tries -= 1
					if proxy == 'not_set':
						response = requests.post(url, headers=headers,
								data=data)
					else:
						response = requests.post(url, headers=headers,
								data=data, proxies=proxies)
					json_response = json.loads(response.text)

					if 'device_name' not in json_response:
						resp_dic[hash].append('Unknown in FB')
						resp_dic[hash].append(0)
					else:

						resp_dic[hash].append(json_response['device_name'
								])
						resp_dic[hash].append(json_response['score'])
					nrec += 1
					print('\n' + hash)
					newrec += '%s\t' % hash
					for x in [0, 1, 2]:
						s = str(resp_dic[hash][x]).strip('[]')
						print('\t' + s)
						if isinstance(s, bytes):
							newrec += s.encode('utf-8')
						else:
							newrec += s
						newrec += '\t'
					newrec += '\n'
					writeme.append(newrec)
					break
				except:

					print('Exception encountered. Retrying')
					if tries == 0:

						# If we keep failing, raise the exception for the outer exception
						# handling to deal with

						raise
					else:

						# Wait a few seconds before retrying and hope the problem goes away

						time.sleep(3)
						tries -= 1
						continue
		except:

			print ('Oops! an exception has occurred', sys.exc_info()[0])
			raise

	# no need to write an empty file if nothing new
	if len(writeme) > 0:
		f = open(OUTFNAME, 'w')
		f.write(''.join(writeme))
		f.write('\n')
		f.close()
	else:
		print('### No new device dhcp fingerprints found that do not match fingerbank dhcp fingerprints') 


def main():
	"""Intake arguments from the user (file & API key) and output the dhcp-db-extend and dhcp-db-FBQ of the DHCP FP in FingerBank."""

	desc = \
		'Query the Fingerbank API for DHCP Fingerprints from either a tab delimited file (dhcphash and dhcpfp as columns) or comprehensively from all available zeek logs'
	parser = argparse.ArgumentParser(description=desc)

	help_text = 'Api key for the FingerBank access'
	parser.add_argument('-k', '--api_key', required=True, type=str,
						help=help_text)

	help_text = 'Optional Ffile containing unknown DHCP Hashes and DHCP FP'
	parser.add_argument('-f', '--file_unknown_hashes', required=False,
						type=str, help=help_text)

	help_text = \
		'Proxy support for the isolated servers, give the proxy url as arg ex: http://ip:port'
	parser.add_argument('-p', '--proxy', required=False, type=str,
						help=help_text)

	args = parser.parse_args()
	api_key = args.api_key
	if args.file_unknown_hashes:
		fp_dic = {}
		with open(args.file_unknown_hashes) as f:
			for line in f:
				print(line)
				(key, val) = line.split('\t')
				key = key.strip()
				val = val.strip()
				fp_dic[key] = val
		f.close()
	else:
		fp_dic = getallFPlogs()
	if args.proxy:
		proxy = args.proxy
	else:
		proxy = 'not_set'

	queryFingerbank(fp_dic, api_key, proxy)


if __name__ == '__main__':
	main()
