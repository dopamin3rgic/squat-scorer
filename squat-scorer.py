#!/usr/bin/python3
import requests
import time
import csv
import json
import base64 
from sys import argv

# global configuration variables
API_KEY = ""
vt_endpoint = "https://www.virustotal.com/api/v3/urls/"
sleep_time = 20 # b/c restricted to 4 calls per minute on free tier

# base64 encodes urls (VirusTotal requirement)
def encode_url(url):
	url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
	return url_id

# parse domains from csv file
def parse_inputfile(filename):
	typosquatted_domain_infos = dict()
	with open(filename) as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			typosquatted_domain_infos[row["Tweak"]] = row
			typosquatted_domain_infos[row["Tweak"]]["Domain"] = row["Tweak"]
	print(f"Loaded {len(typosquatted_domain_infos)} domains from {filename}")
	return typosquatted_domain_infos

# query the VirusTotal API for the domain and return the score
def request_API(url_id):
	headers = {"x-apikey": API_KEY}
	s = requests.session()
	response = s.get(f"{vt_endpoint}{url_id}",headers=headers)
	resp_data = response.json()
	if not response.ok or "data" not in resp_data:
		print(f"Something went wrong: {response.status_code} Received")
		print(f"\tResponse received: {response.text}")
		if response.status_code == 401:
			print("Please enter a valid API key.")
			exit(1)
		score = "N/A"
		return score
	else:
		malicious = resp_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
		total = resp_data["data"]["attributes"]["last_analysis_stats"]["harmless"] + malicious
		# score might not match exactly with the web UI because the web UI includes "unrated" votes
		score = f"{malicious}/{total}"
		# last_final_url may not match original domain if a redirect occured
		print(f"Requested", resp_data["data"]["attributes"]["last_final_url"],"and received score:", score)
		
	return score

def main():
	if len(argv) < 2:
		print("Usage: squat-scorer.py {csv-file}")
		exit(1)
	else:
		filename = argv[1]

	typosquatted_domain_infos = parse_inputfile(filename)
	print(f"Scoring {len(typosquatted_domain_infos)} domains with Virus Total")
	for domain, info in typosquatted_domain_infos.items():
		url_id = encode_url(domain)
		score = request_API(url_id)
		typosquatted_domain_infos[domain]["Virus Total Score"] = score
		print(f"\tsleeping for {sleep_time} seconds", end="")
		for sec in range(sleep_time):
			time.sleep(1.0)
			print(".", end="", flush=True)
		print()
	write_outfile(typosquatted_domain_infos, filename)


def write_outfile(typosquatted_domain_infos, filename):
	outfile = f"Scored_{filename}"
	print(f"Writing {outfile} to disk")
	with open(outfile, 'w', newline='') as csvfile:
		headers = ["Domain", "Type", "IP", "Virus Total Score"]
		writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore', restval='')
		writer.writeheader()
		for info in typosquatted_domain_infos.values():
			writer.writerow(info)


if __name__ == '__main__':
	main()