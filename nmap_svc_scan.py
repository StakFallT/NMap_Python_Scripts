import os
import sys

import nmap
#from netaddr import IPNetwork

import argparse

from cmd2 import Cmd

import colored
import json

import nmap_svc_scan_defaults
import nmap_svc_scan_globals

MODULE='Custom_NMAP_SVC_Scan'
ver='1.0'

nmap_testscan_host = "Scanme.Nmap.Org"

Extra_Args = {}
Extra_Args['timing'] = 4
Extra_Args['suppress_screenoutput'] = False


parser = argparse.ArgumentParser(
		prog=MODULE,
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description='NMap - Custom NMap service scanner Data Scrapper module.\n',
		epilog='\nCopyright 2017 Brandon Morris.')

# The -- indicates that it is optional
parser.add_argument('--version', action='version', version='%(prog)s ' + ver)

#TODO: Look at this again when it work on implementing this in Data Scrapper will be done
#parser.add_argument('--modulename',
#			required=False,
#			nargs=1,
#			default="",
#			type=str,
#			metavar="<modulename>",
#			help="Register an external module with the main module.")

parser.add_argument('-s', '--scantype',
			type=int,
			choices=[0],
			help="Portscan range -- 0 - ALL (1-65535)")

#As per: https://docs.python.org/2/howto/argparse.html#introducing-optional-arguments
# store_true means that, if the option is specified, assign the value True to the argument. Not specifying
# if implies False.
parser.add_argument('-a', '--async',
			required=False,
			action='store_true',
			help="Perform multiple host scans (asynchronis)")

parser.add_argument('-o', '--output',
			required=False,
			nargs=1,
			default=nmap_svc_scan_defaults.nmap_svc_scan_defaults.Default_Scan_Type,
			type=int,
			metavar="<output stream>",
			help="Redirect output of each scan. 0 - Send results to screen, 1 - Send all results to a file, 2 - Send each host's result to a file using the IP as part of the filename.")

parser.add_argument('-i', '--ip',
			required=True,
			default="",
			type=str,
			metavar="<host(s)>",
			help="Scan a host (or a range of hosts using CIDR). Example usage: --host 192.168.100.1 or --host 192.168.100/24")

parser.add_argument('-v', '--verbose',
		    type=int,
			choices=[0, 1, 2],
		    help="increase output verbosity")

parser.add_argument('-T', '--timing',
			type=int,
			default=4,
			choices=[1, 2, 3, 4],
			help="Manually set timing.")

parser.add_argument('-n', '--suppress_screenoutput',
			required=False,
			action='store_true',
			help="Suppress scan results from displaying on screen.")

def callback_result(host, scan_result):
	#scan_result is JSON and consists of this layout:
	#
	#{
	#	'nmap': {
	#		'scanstats': {
	#			'uphosts': '1',
	#			'timestr': 'Thu Jul 06 00:37:08 2017',
	#			'downhosts': '0',
	#			'totalhosts: '1',
	#			'elapsed': '6.75
	#		},
	#		'scaninfo': {
	#			'tcp': {
	#				'services': '1,3-4,6-7,9...',
	#				'method': 'syn'
	#			}
	#	},
	#	'command_line': 'nmap -oX - -sV -T4 ###.###.###.###',
	#	},
	#'	scan': {
	#		'###.###.###.###': {
	#			'status': {
	#				'state': 'up',
	#				'reason': 'reset'
	#			},
	#			'hostnames': [
	#				{
	#					'type': '',
	#					'name': ''
	#				}
	#			],
	#			'vendor': {},
	#			'addresses': {
	#				'ipv4': '###.###.###.###'	
	#			}	
	#		}
	#	}
	#}

	print ('host:' + host)
	Filename = host.replace('.', '_')
	Filename = Filename + "_services.txt"
	New_File = open(Filename, 'w')
	#print (nm.scan(IP_Addr.format(), ''))
	#print ("You are here (1).")
	print ("host: " + host)
	#print ("nm[host]: " + dir(nmap_svc_scan_globals.nm[host]))
	#print ("host: " + dir(host))
	#print ("nmap_svc_scan_globals.nm: " + dir(nmap_svc_scan_globals.nm))

	#for proto in nmap_svc_scan_globals.nm[host].all_protocols():
	#	print ('Protocol: %s' % proto)
	#	#print ("You are here (2).")
	#	#OutputString = 'Protocol : %s' % proto
	#	OutputString = 'Protocol: ' + proto
	#	New_File.write(OutputString)
	#	#print ("You are here (3).")

	#	lport = nmap_svc_scan_globals.nm[host][proto].keys()
	#	lport.sort()
	#	#print "You are here (4)."

	#	for port in lport:
	#		#print ('port: %s\tstate: %s'% (port, nmap_svc_scan_globals.nm[host][proto][port]['state']) + '\n')
	#		#OutputString = string('port: %s\tstate : %s'% (port, nm[host][proto][port]['state'])
	#		print ('port: ' + str(port) + '\tstate: ' + nmap_svc_scan_globals.nm[host][proto][port]['state'] + '\n')
	#		OutputString = 'port: ' + str(port) + '\tstate: ' + nmap_svc_scan_globals.nm[host][proto][port]['state'] + '\n'
	#		New_File.write(OutputString)
	print (host, scan_result)
	#New_File.write(scan_result)
	OutputString = host + "\n" + str(scan_result)
	New_File.write(OutputString)

def nmap_sync_scan(args, ArgumentString):

	#print ("ArgumentString:'" + ArgumentString + "'")
	#argumentString = ArgumentString.strip('\t')
	#argumentString = ArgumentString.strip('\r')
	#argumentString = ArgumentString.strip('\n')
	#print ("argumentString:'" + ArgumentString + "'")

	#nmap_svc_scan_globals.nm.scan(hosts=args.ip, arguments=argumentString)
	nmap_svc_scan_globals.nm.scan(hosts=args.ip, arguments=ArgumentString)

	for host in nmap_svc_scan_globals.nm.all_hosts():
		#print ('host:' + host)
		Filename = host.replace('.', '_')
		Filename = Filename + "_services.txt"
		New_File = open(Filename, 'w')

		for proto in nmap_svc_scan_globals.nm[host].all_protocols():
			if (args.suppress_screenoutput == False):
				print ('Protocol: %s' % proto + '\n')
			#print ("You are here (2).")
			#OutputString = 'Protocol : %s' % proto
			OutputString = 'Protocol: ' + proto + "\n"
			New_File.write(OutputString)
			#print ("You are here (3).")

			lport = nmap_svc_scan_globals.nm[host][proto].keys()
			lport.sort()
			#print "You are here (4)."

			for port in lport:
				dir(port)
				#print ('port: %s\tstate: %s'% (port, nmap_svc_scan_globals.nm[host][proto][port]['state']))
				if (args.suppress_screenoutput == False):
					print ('port: ' + str(port) + '\tstate: ' + nmap_svc_scan_globals.nm[host][proto][port]['state'])
				#OutputString = string('port: %s\tstate : %s'% (port, nm[host][proto][port]['state'])
				OutputString = 'port: ' + str(port) + '\tstate: ' + nmap_svc_scan_globals.nm[host][proto][port]['state'] + '\n'
				New_File.write(OutputString) 

#class main(Cmd):
def main():
	intro = "NMap - Custom NMap Service Scanner - Data Scrapper Module " + ver

	#args = ''

#	def __init__(self):
#		Cmd.__init__(self)

	args = parser.parse_args()
	#self.args = args

	#if self.args.verbose > 0:
	#if args.verbose > 0:
	#	print("Verbose option detected.")
	if args.verbose > 2:
		print (dir(args))

	ip = args.ip
	ip = str(ip).strip("['")
	ip = str(ip).strip("]'")
	args.ip = ip

	print ""
	#args.ip = args.ip.split(',')
	print (args.ip)
	#print ""
	#print (args.async)

	if args.async == True:
		nmap_svc_scan_globals.nm = nmap.PortScannerAsync()
	else:
		nmap_svc_scan_globals.nm = nmap.PortScanner()

	ArgumentString = ''

	# Iterate through all of the extra arguments
	if args.scantype != None:
		Extra_Args['scantype'] = args.scantype
		ArgumentString = '-s' + args.scantype
	else:
		Extra_Args['scantype'] = 'V'
		ArgumentString = '-sV'

	#print args.timing
	#print ( str(nmap_svc_scan_defaults.nmap_svc_scan_defaults.Default_Scan_Arguments) )
	#print ( nmap_svc_scan_defaults.nmap_svc_scan_defaults.Default_Scan_Arguments[0] )

	if args.timing != None:
		Extra_Args['timing'] = args.timing
		#Temp_Timing = str(args.timing).strip('\r\n')
		#print ("Temp_Timing:'" + Temp_Timing + "'")
		ArgumentString = ArgumentString + ' ' + '-T' + str(args.timing)
		#ArgumentString = ArgumentString + ' ' + '-T' + Temp_Timing
		#print "args.timing != None"
		#print ArgumentString
	else:
		#Extra_Args['timing'] = 4
		ArgumentString = ArgumentString + ' ' + '-T' + nmap_svc_scan_defaults.nmap_svc_scan_defaults.Default_Scan_Arguments[0]
		#print "args.timing == None"
		#print ArgumentString

	# Now, build the argument string

	#First, convert the arg (list object) to a string (respecting the spaces inside of any quotes if applicable)
	#JoinedArgs = ''.join([str(x) for x in self.args])
	#JoinedArgs = ''.join([str(x) for x in args])
	#dir(JoinedArgs)
	#Next, resplit the string back out to a list object (where every element is another 'grouping' based on spaces)
	#ArgList = JoinedArgs.split(' ')

	#Finally, send that argument list to the parser.
	#self.args = parser.parse_args(ArgList)
	#args = parser.parse_args(ArgList)

	#if self.args.modulename != '':
	#	print("'" + self.args.modulename[0] + "' module registered.")

	#if self.args.verbose > 0:
	#if args.verbose > 0:
		#Registered_Modules.append(self.args.modulename[0])
	#	Registered_Modules.append(args.modulename[0])

	#print ("ArgumentString:'" + ArgumentString + "'")
	#ArgumentString = ArgumentString.strip('\r\n')
	#print ("ArgumentString:'" + ArgumentString + "'")

	try:
		#nm.scan(hosts='172.16.0.0/22', callback=callback_result)
		if args.ip != None:
			if args.async == True:
				#nmap_svc_scan_globals.nm.scan(hosts=args.ip, arguments='-sV', callback=callback_result)
				nmap_svc_scan_globals.nm.scan(hosts=args.ip, arguments=ArgumentString, callback=callback_result)
				while nmap_svc_scan_globals.nm.still_scanning():
					print('<<< Scanning >>>')
					nmap_svc_scan_globals.nm.wait(2)
			else:
				nmap_sync_scan(args, ArgumentString)
		else:
			if args.async == True:
				#nmap_svc_scan_globals.nm.scan(hosts=nmap_testscan_host, arguments='-sV', callback=callback_result)
				nmap_svc_scan_globals.nm.scan(hosts=nmap_testscan_host, arguments=ArgumentString, callback=callback_result)
				while nmap_svc_scan_globals.nm.still_scanning():
					print('<<< Scanning >>>')
					nmap_svc_scan_globals.nm.wait(2)
			else:
				#nmap_svc_scan_globals.nm.scan(hosts=nmap_testscan_host)
				nmap_svc_scan_globals.nm.scan(hosts=nmap_testscan_host, arguments=ArgumentString)

		if args.async == False:
			print "nmap command line effectively used based on parameters and arguments: " + nmap_svc_scan_globals.nm.command_line()

	except KeyboardInterrupt:
		print 'Cancelling current operation'
		sys.exit()

	except KeyError as e:
		pass


	#for host in nm.all_hosts():
	#	print ('host:' + host)
	#	Filename = host.replace('.', '_')
	#	Filename = Filename + "_services.txt"
	#	New_File = open(Filename, 'w')
	#	#print (nm.scan(IP_Addr.format(), ''))
	#	for proto in nm[host].all_protocols():
	#		print ('Protocol: %s' % proto)
	#		#OutputString = 'Protocol : %s' % proto
	#		OutputString = 'Protocol: ' + proto
	#		New_File.write(OutputString)
	#
	#		lport = nm[host][proto].keys()
	#		lport.sort()
	#
	#		for port in lport:
	#			print ('port: %s\tstate: %s'% (port, nm[host][proto][port]['state']))
	#			#OutputString = string('port: %s\tstate : %s'% (port, nm[host][proto][port]['state'])
	#			OutputString = 'port: ' + port + '\tstate: ' + nm[host][proto][port]['state']
	#			New_File.write(OutputString)

if __name__ == '__main__':
	#freeze_support()
	main()
	#app = main()
	#app.cmdloop()