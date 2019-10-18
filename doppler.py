####
## doppler.py
## Identify cloud resources from a list of IP addresses
## Reads a list of IPs, pulls current cloud provider netblocks, and returns IP addresses
## that belong to AWS, Azure, and GCP netblocks.
##
## outputs a CSV file, or prints to terminal if no output file is passed.
####
import requests
import json
import dns.resolver
import socket
import ipaddress
import re
import argparse


def getArgs():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i','--input', help = 'path to input file containing one IP or CIDR subnet per line', required = True)
	parser.add_argument('-o', '--output', help = 'path to output location for CSV file', required = False)
	return parser.parse_args()


def getRanges(platforms):
	awsurl = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
	azureurl = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'
	
	#TXT record to query for google
	google_record = '_cloud-netblocks.googleusercontent.com.'
	master_list = dict()

	#pull json data from Amazon
	if 'aws' in platforms:
		aws_subnets = []
		rdata = requests.get(awsurl)
		awsdata = rdata.json()
		for item in awsdata.get('prefixes'):
			aws_subnets.append(item)
		master_list['aws'] = aws_subnets

	#pull json data from Microsoft
	if 'azure' in platforms:
		azure_subnets = []
		rdata = requests.get(azureurl)
		links = re.findall(r'url=https://download.microsoft.com/download/.*.json',rdata.text)
		rdata = requests.get(links[0].split('=')[1])
		azuredata = rdata.json().get('values')
		master_list['azure'] = azuredata

	#Google is difficult https://cloud.google.com/compute/docs/faq#find_ip_range
	if 'gcp' in platforms:
			gcp_subnets = []
			resolver = dns.resolver.Resolver()
			rdata = resolver.query(google_record, 'TXT')
			dnsParse(rdata,resolver,gcp_subnets)
			master_list['gcp'] = gcp_subnets
			#Iterate through the DNS response to get the TXT record, convert to string for parsing.
	return master_list


def dnsParse(rdata,resolver,gcp_subnets):
	for answer in rdata:
			records = str(answer).split(' ')
	for line in records:
		if "include:_" in line:
			dnsParse(resolver.query(line.replace('include:',''),'TXT'),resolver,gcp_subnets)
		if "ip4:" in line:
			gcp_subnets.append(line.replace('ip4:',''))


def readInput(filename):
	user_list = [] 
	rfile = open(filename,'r')
	user_ips = rfile.read().splitlines()
	for line in user_ips:
		if "/" in line:
			subnet = ipaddress.ip_network(line)
			for ip in subnet:
				user_list.append(ip)
		else:
			ip = ipaddress.ip_address(line)
			user_list.append(ip)
			
	return(user_list)


def compareNets(user_list,cloud_ranges):
	matches = {'aws':{}, 'azure':{}, 'gcp':[]}

	for ip in user_list:
		found = 0
		#compare AWS
		for row in cloud_ranges['aws']:
			if ip in ipaddress.ip_network(row['ip_prefix']):
				if ip not in matches['aws']:	
					matches['aws'][ip] = {'region':[],'service':[]}
				matches['aws'][ip]['region'].append(row['region'])
				matches['aws'][ip]['service'].append(row['service'])
				found += 1

		#Compare GCP
		if found == 0:
			for row in cloud_ranges['gcp']:
				if ip in ipaddress.ip_network(row):
					found += 1
					if ip not in matches['gcp']:
						matches['gcp'].append(ip)

		#Compare Azure
		if found == 0:
			for row in cloud_ranges['azure']:
				for subnet in row['properties']['addressPrefixes']:
					if ip in ipaddress.ip_network(subnet):
						if ip not in matches['azure']:
							matches['azure'][ip] = {'region':[],'service':[]}
						matches['azure'][ip]['region'].append(row['properties']['region'])
						matches['azure'][ip]['service'].append(row['name'])
	return matches


def writeOutput(matches,outputfile):
	text = ['platform,ip_address,region,service']
	for item in matches['aws']:
		platform = 'aws'
		ip = item
		for x in range(0,len(matches[platform][item]['region'])):
			region = matches[platform][item]['region'][x]
			service = matches[platform][item]['service'][x]
			text.append('%s,%s,%s,%s' % (platform, ip, region, service))

	for item in matches['azure']:
		platform = 'azure'
		ip = item
		for x in range(0,len(matches[platform][item]['region'])):
			region = matches[platform][item]['region'][x]
			service = matches[platform][item]['service'][x]
			text.append('%s,%s,%s,%s' % (platform, ip, region, service))

	for item in matches['gcp']:
		platform = 'gcp'
		ip = item
		region = ''
		service = 'compute'
		text.append('%s,%s,%s,%s' % (platform, ip, region, service))

	if outputfile != None:
		w = open(outputfile,'w')
		w.write('\n'.join(text))
		w.close()
	else:
		for line in text:
			print(text)


args = getArgs()
filename = args.input
outputfile = args.output
platforms = ['aws','azure','gcp']
cloud_ranges = getRanges(platforms)
user_list = readInput(filename)
matches = compareNets(user_list,cloud_ranges)
writeOutput(matches,outputfile)