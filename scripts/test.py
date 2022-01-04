from bs4 import BeautifulSoup
import bs4
from pymongo import MongoClient
from urllib.request import Request, urlopen
import csv
import os


if __name__ == '__main__':
    file_input = input("Enter CSV file (including extension) to read CVEs from: ")
    filename = file_input.split("/")[-1]
    directory = file_input.replace(filename, '')
    if directory:
        csv_file = open(filename)
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            CVE = row[0]




            filename1 = CVE + ".txt"
            fr = open(filename1)
            arrayOlines = fr.readlines()
            list = []
            for line in arrayOlines:
                line = line.strip()
                list.append(line)

            field_value = list[0]

            attack_vector = list[1]
