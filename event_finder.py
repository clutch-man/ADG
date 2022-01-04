import json
import os
import subprocess

class EventFinder(object):
    def __init__(self, username, password):
        self.splunk_username = username
        self.splunk_password = password

    # 检查事件集中是否存在漏洞事件
    def containsVulnEvent(self, description, host, port, timestamp):
        search_str = 'python search.py "search '
        query = search_str + description + " SRCHOST=*" + " DSTHOST=" + host + " DSTPORT=" + str(port) + " TIMESTAMP<" + str(timestamp) + " host=DESKTOP"
        query += '" --username="' + self.splunk_username + '" --password="' + self.splunk_password + '" --output_mode=json'
        # print(query)
        os.chdir("splunk/examples")
        status, result = subprocess.getstatusoutput(query)  #执行cmd命令，返回一个元组(命令执行状态, 命令执行结果输出)
        json_result = json.loads(result)["results"]         #将result里的results筛选出来
        os.chdir("../..")
        if json_result == []:
            return None
        return json_result
    '''
    splunk主要用于event_finder.py，使用
    'python search.py "search XPC message sent to make a new OpenVPN connection SRCHOST=* DSTHOST=F DSTPORT=1521 TIMESTAMP<1563861901 host=DESKTOP" --username="admin" --password="123456789" --output_mode=json'
    指令来检查事件集中是否存在事件，
    返回的是json类型。
    '''
