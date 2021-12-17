# Squat Scorer
Squat Scorer is a python script that can be used to score typosquatted domains using the Virus Total API. This tool is meant to be used with dnstwister, a free online tool that will query DNS records for typosquatted domains.

## Set Up
- Create a free account on Virus Total and copy your API key from your account. Assign your key to the variable `API_KEY` in `squat-scorer.py`
    - [Virus Total Documentation](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)
   
- Go to https://dnstwister.report/ and generate a report for the domain of your choice. Once generated, export the results to a CSV file and save it locally.

## Run
To run the script: 
`python3 squat-scorer.py {filename}`

The dnstwister input file usually looks something like `dnstwister_report_company.com.csv`, unless you renamed it after downloading it.