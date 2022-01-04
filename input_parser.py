from state_node import StateNode
from vulnerability_node import VulnerabilityNode
from defense_node import DefenseNode
import csv
import os

class Parser(object):

    def parseStartNodes(self):
        while True:
            '''
            采用while True循环语句：如果出现错误的话，可以返回到开始部分，请求继续输入。
            '''
            try: 
                numStartNodes = int(input("Enter number of start nodes in attack graph: >>>"))
                if numStartNodes > 0:
                    break
                print("Please enter a positive integer")
            except ValueError:
                print("Please enter a positive integer")
        
        while True:
            names = input("Enter start node(s) name(s), separated by comma >>>")

            if names:
                startNodesNames = names.split(',')
                name = startNodesNames[0]
                if len(startNodesNames) == numStartNodes:
                    break
                else:
                    print("Number of start node(s) must be as specified")
                    continue
            print("Please enter a non-empty start node name")

        '''
            把可入主机节点名和权限存储在可入节点的集合中。
        '''
        startNodeSet = set()
        for i in range(0, numStartNodes):
            stateNode = StateNode(startNodesNames[i], 0)
            startNodeSet.add(stateNode)

        # 如果开始集为空，则拒绝框架
        if not startNodeSet:
            print("Attack graph cannot have no start nodes")
            exit()

        return startNodeSet,name
    '''
    输入可入节点个数和名称，并返回可入节点集合和可入节点名。
    '''

    '''
    输入值得注意的事件，对应定义3，和eventSet.csv
    '''
    def parseNotableEvent(self):
        while True:
            print("Enter notable event >>>")
            event = input()
            if event:
                eventComponents = event.split(",")
                if len(eventComponents) == 8:
                    break
                else:
                    print("Please enter a valid notable event")
                    continue
            print("Please enter a non-empty notable event")

        '''
        输入假定的攻击者访问级别，访问级别为三类0(None),1(User)和2(Root)。
        '''
        while True:
            try: 
                accessLevel = int(input("Enter access level of attacker at the notable event>>>"))
                if accessLevel >= 0 and accessLevel <= 2:
                    break
                print("Please enter 0 (no access), 1 (user) or 2 (root)")
            except ValueError:
                print("Please enter 0 (no access), 1 (user) or 2 (root)")
        
        timestamp = int(eventComponents[0])
        src = eventComponents[1]
        dst = eventComponents[2]
        port = int(eventComponents[6])#目标主机端口
        description = eventComponents[7]

        return timestamp, src, dst, port, description, accessLevel

    '''
    读取并解析reachability.csv文件，并存入可达性字典
    '''
    def parseReachability(self):
        file_input = input("Enter CSV file (including extension) containing reachability graph: ")
        filename = file_input.split("/")[-1]
        '''
        以 / 分割将倒数第一块切割出来，也就是文件名。
        '''
        directory = file_input.replace(filename, '')
        '''
        把路径中的文件名去除作为目录。
        '''
        if directory:
            curr_dir = os.getcwd()
            '''
            os.getcwd() 方法用于返回当前工作目录。
            os.chdir() 改变当前工作目录到指定的路径。
            '''
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                csv_reader = csv.reader(csv_file, delimiter=',')
                '''
                把csv文件中每行读取的值作为列表返回，逗号分隔
                '''

                reachability_dict = {}
                '''
                {}表示dict字典数据类型
                '''
                for row in csv_reader:
                    hostname = row[0]#每行的第1个元素为原主机
                    reachable = row[1:]#每行的第2到最后为可达性主机
                
                    reachable_set = set()
                    for i in reachable:#遍历一行的可达性主机
                        neighbour = i.split(",")[0]#可达主机名
                        if not neighbour:
                            continue
                        port = int(i.split(",")[1])#可达主机开放端口
                        reachable_set.add((neighbour, port))
                    '''
                    把可达主机名和端口存入可达集合中，并作为可达字典对应主机的值。
                    '''
                    reachability_dict[hostname] = reachable_set

                return reachability_dict

        except IOError:
            print("File {} does not exist".format(filename))
            exit()
 
    # 创建两个词典：
    # 1) （vulnName，vulnPort）到VulnerabilityNode的映射
    # 2) 端口
    def parseVulnerabilities(self):
        file_input = input("Enter CSV file (including extension) containing vulnerabilities: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                next(csv_file, None) # Skip first row (header)
                '''
                next表示返回文件的下一行，这里none表示下一行不存在。
                '''
                csv_reader = csv.reader(csv_file, delimiter=',')

                vulnDict = {}
                portDict = {}
                for row in csv_reader:
                    '''
                    每行第一个元素作为主机名
                        第二个元素作为漏洞名
                        第三个元素/前作为端口
                    '''
                    hostname = row[0]
                    vulnName = row[1]
                    vulnPort = int(row[2].split("/")[0])
                    vulnNode = VulnerabilityNode(vulnName, vulnPort)
                    '''
                    根据漏洞名和端口，在MongoDB中查询存储的漏洞信息，生成完整的漏洞节点。
                    '''

                    if (hostname, vulnPort) in vulnDict:
                        vulnDict[(hostname, vulnPort)].add(vulnDict)
                        '''
                        如果键在字典中存在，则用新的漏洞作为值替换。
                        '''

                        '''
                        如果键在字典中不存在，则把完整的漏洞信息添加到漏洞集，漏洞集作为值存放在对应键（主机，端口）的字典中。
                        '''
                    else:
                        vulnSet = set()
                        vulnSet.add(VulnerabilityNode(vulnName, vulnPort))
                        vulnDict[(hostname, vulnPort)] = vulnSet

                    if hostname in portDict:
                        '''
                        如果键在字典中存在，则用新的端口作为值替换。
                        '''
                        portDict[hostname].add(vulnPort)
                    else:
                        portSet = set()
                        portSet.add(vulnPort)                    
                        portDict[hostname] = portSet
          
            return vulnDict, portDict

        except IOError:
            print("File {} does not exist".format(filename))
            '''
            >>>"{} {}".format("hello", "world")    # 不设置指定位置，按默认顺序
            'hello world'
 
            >>> "{0} {1}".format("hello", "world")  # 设置指定位置
            'hello world'
 
            >>> "{1} {0} {1}".format("hello", "world")  # 设置指定位置
            'world hello world'
            '''

            exit()

    def parseDefense(self):
        file_input = input("Enter CSV file (including extension) containing defense: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                next(csv_file, None) # Skip first row (header)
                '''
                next表示返回文件的下一行，这里none表示下一行不存在。
                '''
                csv_reader = csv.reader(csv_file, delimiter=',')

                defDict = {}

                for row in csv_reader:
                    print(row)
                    vulID = row[0]
                    defID = row[1]

                    defenseNode = DefenseNode(vulID, defID)
                    '''
                    根据漏洞名和端口，在MongoDB中查询存储的漏洞信息，生成完整的漏洞节点。
                    '''

                    if (vulID, defID) in defDict:
                        defDict[(vulID)].add(defDict)
                        '''
                        如果键在字典中存在，则用新的漏洞作为值替换。
                        '''

                        '''
                        如果键在字典中不存在，则把完整的漏洞信息添加到漏洞集，漏洞集作为值存放在对应键（主机，端口）的字典中。
                        '''
                    else:
                        defSet = set()
                        defSet.add(DefenseNode(vulID, defID))
                        defDict[(vulID)] = defSet

            return defDict

        except IOError:
            print("File {} does not exist".format(filename))
            '''
            >>>"{} {}".format("hello", "world")    # 不设置指定位置，按默认顺序
            'hello world'
    
            >>> "{0} {1}".format("hello", "world")  # 设置指定位置
            'hello world'
    
            >>> "{1} {0} {1}".format("hello", "world")  # 设置指定位置
            'world hello world'
            '''

            exit()

    # 创建CVE到事件描述的字典映射

    # 创建CVE到事件描述的字典映射。为简单起见，假设每个CVE映射到单个事件
    def parseEventMapping(self):
        cveToEventDict = {}
        file_input = input("Enter CSV file (including extension) containing mapping of CVE to event: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                next(csv_file, None) # Skip first row (header)
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    cve = row[0]
                    eventDescription = row[1]
                    # if cve in cveToEventDict:
                    #     cveToEventDict[cve].add(eventDescription)
                    # else:
                    # eventSet = set()
                    # eventSet.add(eventDescription)                    
                    # cveToEventDict[cve] = eventSet
                    cveToEventDict[cve] = eventDescription 
            return cveToEventDict

        except IOError:
            print("File {} does not exist".format(filename))
            exit() 

    def parseSplunkConfig(self):
        try:
            f = open("splunkConfig.txt", "r")
            username = f.readline().strip('\n')
            password = f.readline().strip('\n')
            return username, password
        
        except IOError:
            print("File {} does not exist".format(f))
            exit() 

    '''
    输入目标主机数量和名称
    '''
    def parseCrownJewels(self):
       while True:
           try:
               numCrownJewels = int(input("Enter number of crown jewels in attack graph: >>>"))
               if numCrownJewels > 0:
                   break
               print("Please enter a positive integer")
           except ValueError:
               print("Please enter a positive integer")

       print("Enter crown jewel(s) name(s) >>>")
       names = input()
       if not names:
           print("Please enter a non-empty crown jewel name")
       crownJewelNames = names.split(',')
      
       crownJewelSet = set()
       for i in range(0, numCrownJewels):
           for j in range(3):
               crownJewel = StateNode(crownJewelNames[i], j)
               crownJewelSet.add(crownJewel)

       # 如果目标主机不存在则拒绝
       # 尚未实施
       # 目前，假设用户输入的目标主机必须存在

       if not crownJewelSet:
           print("Attack graph cannot have no crown jewels")
           exit()

       return crownJewelSet






