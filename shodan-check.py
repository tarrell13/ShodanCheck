#!/usr/bin/python3

import requests
import argparse
import re
import bs4
import json
import progress

parser = argparse.ArgumentParser(description="Queries Shodan for Information related to Host(s)", usage="python3 shodan-check.py -i <ip_range>")
parser.add_argument("-i","--input", help="Input List of Hosts from file", required=True)
parser.add_argument("-o","--output", help="Output file name", default="results.json")
args = parser.parse_args()

def build_host_list(args):

    host_list = []

    with open(args.input) as handle:
        for line in handle:
            host_list.append(line.rstrip())

    return host_list


def check_alternate_names(text):

    alternate_names = []
    soup = bs4.BeautifulSoup(text, 'lxml')
    certificate = soup.find_all('pre')

    if re.search("DNS:", str(certificate)):
        results = re.findall("DNS:\S*", str(certificate))

        for result in results:
            alternate_names.append(str(result).split(":")[1])

    return alternate_names



def main():
    
    data = {}
    host_list = build_host_list(args)

    print("================================================")
    print("Checking Live Host and Alternate Names -> Shodan")
    print("================================================\n")
    
    incrementer = 0

    for host in host_list:

        try:

            r = requests.get("https://www.shodan.io/host/%s" %host)

            if r.status_code == 200:
                
                if host not in data:
                    data[host] = []

                alternates = check_alternate_names(r.text)
                if bool(alternates):
                    for alt in alternates:
                        data[host].append(alt)

        except:
            continue

        incrementer += 1
        progress.progress(incrementer, len(host_list))


        
    with open(args.output, "w") as handle:
        handle.write(json.dumps(data, indent=4))





main()
