Scan_Type = [ [0, 'all', 'Scan for all ports (1-65535)'], \
			  [1, 'well_known', '']]

Output_Type = [ [0, 'screen', 'Send results to screen'], \
				[1, 'singlefile', 'Send all results to a single file'],
				[2, 'multifile', "Send each host's result to a file using the IP as part of the filename. "]]

Parameter_Index = [ [0, 'scantype'],
					[1, 'timing',]]

class nmap_svc_scan_defaults():
	Default_Scan_Type = 0
	Default_Output_Type = 0

	Default_Scan_Min_Port = 1
	Default_Scan_Max_Port = 65535

	Default_Scan_Arguments = ['-sV']
	Default_Scan_Arguments.append('-t4')

	def __init__(self):
		#Cmd.__init__(self)
		self.Default_Scan_Type = Default_Scan_Type
		self.Default_Output_Type = Default_Output_Type

		self.Default_Scan_Min_Port = Default_Scan_Min_Port
		self.Default_Scan_Max_Port = Default_Scan_Max_Port

		self.Default_Scan_Arguments = Default_Scan_Arguments