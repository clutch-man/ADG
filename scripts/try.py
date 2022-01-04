from bs4 import BeautifulSoup
import bs4
from pymongo import MongoClient
from urllib.request import Request, urlopen
import csv
import os

if __name__ == '__main__':

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
        csv_file = open(filename)
        csv_reader = csv.reader(csv_file)#解析CVEs.csv文件
        for row in csv_reader:
            CVE = row[0]



            filename1 = CVE + ".txt"
            fr = open(filename1)#打开对应的漏洞txt文件
            arrayOlines = fr.readlines()
            list = []#读取每行数据存入list
            for line in arrayOlines:
                line = line.strip()
                list.append(line)
            print(list)
            field_value = list[0]
            required_priv = mapping1[field_value]#将第一行数据映射为对应值

            attack_vector = list[1]

            gained = list[2]
            gained_access = mapping2[gained]

            defense_id = list[3]

            document = {}#建立字典
            document['cveName'] = CVE
            document['gained_access'] = gained_access
            document['required_priv'] = required_priv
            document['access_vector'] = attack_vector
            document['defense_id'] = defense_id
            vulns.insert_one(document)#使用insert_one()和insert_many()方法来分别插入单条记录和多条记录

    print("Successfully imported CVE details")