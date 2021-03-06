# Script to web scrape vulnerability information into mongodb

from bs4 import BeautifulSoup
import bs4
from pymongo import MongoClient
from urllib.request import Request, urlopen
import csv
import os

client = MongoClient('localhost', 27017)
db = client.project
vulns = db.vulnerabilities
vulns.drop()
vulns = db.vulnerabilities

mapping1 = { 'High': 2, 'Low': 1, 'None': 0 }
mapping2 = { 'Admin': 2, 'User': 1, 'None': 0 }

file_input = input("Enter CSV file (including extension) to read CVEs from: ")
filename = file_input.split("/")[-1]
directory = file_input.replace(filename, '')

if directory:
    curr_dir = os.getcwd()
    os.chdir(directory)
    print(os.getcwd())

try:
    with open(filename) as csv_file:
        # os.chdir(curr_dir)
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            CVE = row[0]
            url = "https://www.cvedetails.com/cve/" + CVE
            req = Request(url, headers={ 'User-Agent': 'Mozilla/5.0' })
            html_doc = urlopen(req).read()
            soup = BeautifulSoup(html_doc, 'lxml')
            table = soup.find("table", { 'id': 'cvssscorestable', 'class': 'details' })
            field_row = table.findAll("tr")[6]
            field_value = field_row.find("span").string
            gained_access = mapping2[field_value]

            #url = "https://nvd.nist.gov/vuln/detail/" + CVE
            #html_doc = urlopen(url)
            #soup = BeautifulSoup(html_doc, 'lxml')
            #soup = soup.prettify(formatter=None)

            filename1 = CVE + ".txt"
            fr = open(filename1)
            arrayOlines = fr.readlines()
            list = []
            for line in arrayOlines:
                line = line.strip()
                list.append(line)

            field_value = list[0]
            required_priv = mapping1[field_value]

            attack_vector = list[1]



            #tag = soup.find('span', {'data-testid': 'vuln-cvssv3-pr'})
            #if tag:
            #    field_value = tag.string.strip()
            #else:
            #    field_value = "None" # By default, "None" privileges are required
            #required_priv = mapping1[field_value]

            #tag = soup.find('span', { 'data-testid': 'vuln-cvssv2-av' })
            #attack_vector = tag.string.strip()

            # Add entry
            document = {}
            document['cveName'] = CVE
            document['gained_access'] = gained_access
            document['required_priv'] = required_priv
            document['access_vector'] = attack_vector
            vulns.insert_one(document)

    print("Successfully imported CVE details")

except IOError:
    print("File {} does not exist".format(filename))
    exit() 
