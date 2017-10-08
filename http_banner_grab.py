import urllib2

#def Grab_Banners(self):
IP_List = []
File = open('IP_addresses.txt', 'r')
for line in File:
	line = line.rstrip()
	IP_List.append(line)

	Filename = line.replace('.', '_')
	Filename = Filename + '.html'

	new_line = 'http://'
	new_line = new_line + line
	#new_line.append(line)

	New_File = open(Filename, 'w')

	print "Retrieving banner for IP:" + new_line
	try:
		response = urllib2.urlopen(new_line)
		print response.info()
		html = response.read()
		# print html
	except:
		print "Cannot connect to HTTP (80) on IP: " + new_line + " attempting connection via https."
		new_line = 'https://'
		new_line = new_line + line
		try:
			response = urllib2.urlopen(new_line)
			print response.info()
			html = response.read()
		except:
			# Couldn't connect to https either on the IP address, denote this in the result file.
			html = "script could not connect to IP neither via http nor https!"

	New_File.write(html)
	New_File.close()