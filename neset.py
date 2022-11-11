#!/usr/bin/python3

import sys
import argparse
import termcolor

from scapy.all import *
from mac_vendor_lookup import *

class Neset:
	def __init__(self):
		self.args()
		self.r = ""
		self.res = ""
		self.result = ""
		self.alive = {}
		while True:
			try:
				self.call()				
			except KeyboardInterrupt:
				break

	def args(self):
		parser = argparse.ArgumentParser(description="Neset network reconnaissance tool.", usage="./%(prog)s [SUBNET]")
		parser._optionals.title = "flags"
		parser.add_argument(metavar="SUBNET", dest="subnet", help="Subnet to scan.")

		self.args = parser.parse_args()
		f = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
		if not f.search(self.args.subnet):
			error("Proper subnet required.")

	def create_packet(self):
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		arp = ARP(pdst=self.args.subnet)

		self.packet = ether / arp

	def send_packet(self):
		self.ans, _ = srp(self.packet, timeout=1, verbose=0)

	def get_alive(self):
		for sent, recv in self.ans:
			self.alive[recv.psrc] = recv.hwsrc

	def printf(self):
		for ip, mac in self.alive.items():
			self.r += f"[{termcolor.colored('+', 'green')}] Host:\n\n"
			self.r += f"  IP: {termcolor.colored(ip, 'red')}" + "\n"
			self.r += f"  Mac: {termcolor.colored(mac, 'red')}" + "\n"
			try:
				self.r += f"  Vendor: {termcolor.colored(MacLookup().lookup(mac), 'red')}" + "\n"

			except:
				self.r += f"  Vendor: Unknown" + "\n"

			self.r += "\n"

	def call(self):
		self.create_packet()
		self.send_packet()
		self.get_alive()
		self.printf()
		r = self.r.replace(self.res, "")
		if r not in self.result:
			print(r, end="")
		self.res = self.r
		self.result += r

def error(p):
	sys.stderr.write("[%s] %s: %s\n" % (termcolor.colored('!', 'red'), termcolor.colored('Exception', 'red'), p))
	sys.exit()

if __name__ == '__main__':
	try:
		Neset()

	except PermissionError:
		error("Need root priveledges.")
	except KeyboardInterrupt:
		sys.exit(1)