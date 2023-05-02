#!/usr/bin/python3
import requests
import time
import csv
import json
import base64 
from sys import argv

# global configuration variables
API_KEY = ""
vt_endpoint = "https://www.virustotal.com/api/v3/domains/"
sleep_time = 20 # b/c restricted to 4 calls per minute on free tier

# parse domains from csv file
def parse_inputfile(filename):
	typosquatted_domain_infos = dict()
	with open(filename) as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			typosquatted_domain_infos[row[" Domain (IDNA)"]] = row
			typosquatted_domain_infos[row[" Domain (IDNA)"]]["Domain (Unicode)"] = row["Domain (Unicode)"]
			typosquatted_domain_infos[row[" Domain (IDNA)"]]["Domain (IDNA)"] = row[" Domain (IDNA)"]
			typosquatted_domain_infos[row[" Domain (IDNA)"]]["IP Address"] = row[" Resolved IP"]
			typosquatted_domain_infos[row[" Domain (IDNA)"]]["MX Record"] = row[" MX registered"]
	print(f"Loaded {len(typosquatted_domain_infos)} domains from {filename}")
	return typosquatted_domain_infos

# query the VirusTotal API for the domain and return the score
def request_API(domain):
	headers = {"x-apikey": API_KEY}
	s = requests.session()
	response = s.get(f"{vt_endpoint}{domain}",headers=headers)
	resp_data = response.json()
	if not response.ok or "data" not in resp_data:
		print(f"Something went wrong: {response.status_code} Received")
		print(f"\tResponse received: {response.text}")
		if response.status_code == 401:
			print("Please enter a valid API key.")
			exit(1)
		score = "N/A"
	else:
		malicious = resp_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
		total = resp_data["data"]["attributes"]["last_analysis_stats"]["harmless"] + malicious
		# score might not match exactly with the web UI because the web UI includes "unrated" votes
		score = f"{malicious}/{total}"
	print(f"Requested", domain,"and received score:", score)		
	return score

# write results to an output file
def write_outfile(typosquatted_domain_infos, filename):
	outfile = f"Scored_{filename}"
	print(f"Writing {outfile} to disk")
	with open(outfile, 'w', newline='') as csvfile:
		headers = ["Domain (Unicode)","Domain (IDNA)", "IP Address", "MX Record", "Virus Total Score"]
		writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore', restval='')
		writer.writeheader()
		for info in typosquatted_domain_infos.values():
			writer.writerow(info)


def throttle_requests():
	print(f"\tsleeping for {sleep_time} seconds", end="")
	for sec in range(sleep_time):
		time.sleep(1.0)
		print(".", end="", flush=True)
	print()


def main():
	if len(argv) < 2:
		print("Usage: squat-scorer.py {csv-file}")
		exit(1)
	else:
		filename = argv[1]

	typosquatted_domain_infos = parse_inputfile(filename)
	print(f"Scoring domains with Virus Total")
	for domain, info in typosquatted_domain_infos.items():
		if typosquatted_domain_infos[domain]['IP Address'] != '':
			score = request_API(domain)
			throttle_requests()
		else:
			print("Domain is not resolvable, skipping scoring.")
			score = 'N/A'
		typosquatted_domain_infos[domain]["Virus Total Score"] = score
		

	write_outfile(typosquatted_domain_infos, filename)


if __name__ == '__main__':
	main()