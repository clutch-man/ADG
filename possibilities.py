import networkx as nx
from state_node import StateNode
from vulnerability_node import VulnerabilityNode

class Possibilities(object):

    def printPossiblePaths(self, DG, src, crownJewelSet,statedict,vulndict):
        for dest in crownJewelSet:
            if DG.has_node(dest):
                #paths = nx.all_shortest_paths(DG,src,dest)
                paths = nx.all_simple_paths(DG, src, dest)    #默认返回所有从源结点到目标结点的路径
                if sum(1 for x in paths) == 0:
                    print("There are no possible paths from  notable event node (" + src.hostname + ", " + str(src.accessLevel) 
                            + ") to crown jewel (" + dest.hostname + ", " + str(dest.accessLevel) + ")")
                    return

                print("POSSIBLE PATHS TO REACH CROWN JEWEL " + dest.hostname + ":")

                step = 99999999#将路径拆分为状态节点和漏洞节点，按序以CVE代号+开放端口号+主机节点（主机名，权限等级）的形式输出路径中的其中一步。
                                #打印输出为达目标主机的最短路径的序号、利用次数最多的漏洞、被攻击次数最多的主机。
                #paths = nx.all_shortest_paths(DG,src,dest)
                paths = nx.all_simple_paths(DG, src, dest)
                pathCounter = 0#路径计数器
                for path in paths:
                    pathCounter = pathCounter + 1
                    print("Possible path " + str(pathCounter) + ":")
                    stepsCounter = 1#步骤计数器
                    for node in path:
                        if type(node) is StateNode:
                            if node.hostname == src.hostname and node.accessLevel == src.accessLevel:
                                '''
                                第一步始终是从可入主机节点进入攻击图，
                                默认可入主机节点为在输入可入节点主机名时的第一个主机。
                                '''
                                print(str(stepsCounter) + ") notable event at (" + node.hostname + ", " + str(node.accessLevel) + ")")
                                stepsCounter = stepsCounter + 1
                                for state in statedict.keys():
                                    if node.hostname == state:
                                        statedict[state] = statedict[state]+1#节点攻击次数+1
                            else:
                                print("on node " + "(" + node.hostname + ", " + str(node.accessLevel) + ")")
                                for state in statedict.keys():
                                    if node.hostname == state:
                                        statedict[state] = statedict[state]+1
                        elif type(node) is VulnerabilityNode:
                            '''
                            第二行及以后则是以exploit+ CVE代号+ on port 开放端口号+ on node （主机名，权限等级），
                            主机名即为为到达目标主机E所途径的主机，权限等级为攻击此主机获得的权限，CVE代号即为利用的漏洞。
                            '''
                            print(str(stepsCounter) + ") exploit " + node.vulnerabilityName + " on port " + str(node.vulnerabilityPort), end = ' ')
                            stepsCounter = stepsCounter + 1

                            lastvulnname = node.vulnerabilityName#为了控制目标主机所必须要利用的漏洞

                            for vuln in vulndict.keys():
                                if node.vulnerabilityName == vuln:
                                    vulndict[vuln] = vulndict[vuln]+1#漏洞利用次数+1

                    if step > stepsCounter:
                        step = stepsCounter
                        shortpath = str(pathCounter)

                    if step == stepsCounter and not shortpath == str(pathCounter):
                        shortpath = shortpath + "," + str(pathCounter)
                    #shortpath为到达目标主机E所途径的最少主机的路径号

                num1 = 0#攻击节点次数
                stateadvice = ""#建议关注的状态节点主机名
                for key1 in statedict.keys():
                    if statedict[key1] > num1 and not key1 == src.hostname and not key1 == dest.hostname:
                        num1 = statedict[key1]
                        stateadvice = key1 + " "

                    elif statedict[key1] == num1 and not key1 == src.hostname and not key1 == dest.hostname:
                        stateadvice = stateadvice + key1 + " "
                        #stateadvice为除了目标主机和可入节点主机外的被攻击次数最多的主机

                num2 = 0#利用漏洞次数
                vulnadvice = ""
                for key2 in vulndict.keys():
                    if vulndict[key2] > num2 and not key2 == lastvulnname:
                        num2 = vulndict[key2]
                        vulnadvice = key2 + " "

                    elif vulndict[key2] == num2 and not key2 == lastvulnname:
                        vulnadvice = vulnadvice + key2 + " "
                        #vulnadvice为被利用的最多的漏洞

                for key3 in statedict.keys():
                    statedict[key3] = 0

                for key4 in vulndict.keys():
                    vulndict[key4] = 0




                print("")

                print("the shortest path to host "+ dest.hostname + " is path" + shortpath)#第一行输出的是：为到达目标主机E所途径的最少主机的路径号
                print("We should pay more attention to protecting host " + stateadvice)#第二行输出的是：除了目标主机和可入节点主机外的被攻击次数最多的主机
                print("Firstly deal with " + vulnadvice + " and then deal with " + lastvulnname)#第三行输出的是：被利用的最多的漏洞代号 以及 为了控制目标主机E所必须要利用的漏洞代号

                print("")


