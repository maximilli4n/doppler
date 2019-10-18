####
## cloud-discover.py
## Identify cloud compute resources from a list of IP addresses
## Reads a list of IPs, pulls current compute netblocks, and returns IP addresses
## that belong to AWS, Azure, and GCP netblocks.
####
import requests
import json
import dns.resolver
import socket
import ipaddress
import re
import argparse
# Specify directory for netblocks (Default is ./ip-ranges)
# Specify input file [required]
# Specify specific cloud platform (default is all)

#AWS FORMAT: {'ip_prefix': '52.95.255.0/28', 'region': 'sa-east-1', 'service': 'EC2'}
#GCP FORMAT: ['35.232.0.0/15', '35.234.0.0/16', ...]
#AZR FORMAT: {a big mess}

def getArgs():
	parser = argparse.argumentParser

def getRanges(platforms):
	awsurl = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	azureurl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
	google_record = "_cloud-netblocks.googleusercontent.com."
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

			#resolver.nameservers = [socket.gethostbyname('ns1.google.com')]

			#Query google's nameservers, store the response in rdata.
			rdata = resolver.query(google_record, 'TXT')
			dnsParse(rdata,resolver,gcp_subnets)
			master_list['gcp'] = gcp_subnets
			#Iterate through the DNS response to get the TXT record, convert to string for parsing.
	return master_list


def dnsParse(rdata,resolver,gcp_subnets):
	#split data into a list of items. If the item contains 'include:', cut out 'include:' perform 
	#a DNS lookup and re-run the function. If the item contains "ip4:", cut ip4 and append the range
	#to the list of netblocks.
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
		#compare AWS
		for row in cloud_ranges['aws']:
			if ip in ipaddress.ip_network(row['ip_prefix']):
				if ip not in matches['aws']:	
					matches['aws'][ip] = {'region':[],'service':[]}
				matches['aws'][ip]['region'].append(row['region'])
				matches['aws'][ip]['service'].append(row['service'])

		#Compare GCP
		for row in cloud_ranges['gcp']:
			if ip in ipaddress.ip_network(row):
				if ip not in matches['gcp']:
					matches['gcp'].append(ip)

		#Compare Azure
		for row in cloud_ranges['azure']:
			for subnet in row['properties']['addressPrefixes']:
				if ip in ipaddress.ip_network(subnet):
					if ip not in matches['azure']:
						matches['azure'][ip] = {'region':[],'service':[]}
					matches['azure'][ip]['region'].append(row['properties']['region'])
					matches['azure'][ip]['service'].append(row['name'])
	return matches


filename = "testfile"
platforms = ['aws','azure','gcp']
cloud_ranges = getRanges(platforms)
user_list = readInput(filename)

matches = compareNets(user_list,cloud_ranges)

print("AWS Matches:")
print("======================================================")
print(matches['aws'])
print("======================================================")
print("GCP Matches:")
print("======================================================")
print(matches['gcp'])
print("Azure Matches:")
print("======================================================")
print(matches['azure'])