import os
from os import walk
from os.path import isfile, join

import sys

import argparse

from cmd2 import Cmd

import colored
import json

MODULE='NMAP Parse JSON Scan results'
ver='1.0'


def main():
	onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

	file = onlyfiles[0]
	#for file in onlyfiles:
	#	if file[-13:-1] = "_services.txt":
	print file
	Parse_JSON_File(file)

def Parse_JSON_File(file):
	hFile = open(file, "r")
	hFile_Contents = hFile.read()

	hFile_Contents_JSON_Parsed = json.loads(hFile_Contents)

	print hFile_Contents_JSON_Parsed
