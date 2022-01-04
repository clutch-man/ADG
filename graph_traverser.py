class GraphTraverser(object):
    def __init__(self, graph, eventSet, eventMapping, networkNodes):
        self.graph = graph
        self.eventSet = eventSet
        self.eventMapping = eventMapping
        self.networkNodes = networkNodes

    '''
    Depth first traversal algorithm，深度优先遍历算法
    输入:目标主机节点dst,事件列表reverseList,端口port,源主机src,事件列表eventList
    输出：更新后的事件列表reverseList
    '''
    def dfs(self, v, reverseList, timestamp, dst, port, src=None):
        # print("dfs called")
        # print(v.to_string())
        # for i in self.graph.predecessors(v):
        #     print(i.to_string())

        if v.type == 'vuln' and v.entry and src not in self.networkNodes:
            # reverseList.reverse()
            # print("Printing at node {}".format(v.to_string()))
            '''
            判断是否是可入的漏洞节点，是的话就结束了，倒序输出事件即可
            '''
            print('')
            return self.print_path(reverseList[::-1])    #倒序

        '''
        若不是可入的漏洞节点则寻找此状态节点的前驱节点，
        首先判断前驱节点是不是漏洞节点，
        是的话获得这个漏洞节点的描述，
        然后在Splunk搜索包含此漏洞的事件，
        如果存在则将事件以时间戳+源头节点+目标节点+事件描述组合添加入事件列表内，再递归调用dfs，
        如果在Splunk不存在此事件，则继续寻找前驱节点。
        '''
        for i in self.graph.predecessors(v):      #前驱节点
            # print("Predecessor: {}".format(i.to_string()))
            if i.type == 'vuln':
                description = self.eventMapping[i.vulnerabilityName]
                eventList = self.eventSet.containsVulnEvent(description, dst, i.vulnerabilityPort, timestamp)#调用containsVulnEvent方法查找事件
                if eventList:
                    for event in eventList:
                        event_string = event['TIMESTAMP'] + ', ' + event['SRCHOST'] + ', ' + event['DSTHOST'] + ', ' + description
                        # print("Adding event: {}".format(event_string))
                        reverseList.append(event_string)
                        self.dfs(i, reverseList, event['TIMESTAMP'], event['DSTHOST'], event['DSTPORT'], event['SRCHOST'])
                        reverseList.pop()#移除列表中的元素

                        # print("Returned from state node")

            elif i.type == 'state':#如果是状态节点直接递归调用dfs
                self.dfs(i, reverseList, timestamp, src, port)
                # print("Returned from vuln node")

    def start_traversal(self, timestamp, src, dst, port, description, accessLevel):
        reverseList = []
        reverseList.append('Notable event: ' + str(timestamp) + ', ' + src + ', '+ dst + ', ' + description)
        '''
        在图里通过主机名和权限等级寻找源头状态节点。
        '''
        notableEventNode = self.find_node(src, accessLevel)
        if notableEventNode:
            eventSequence = self.dfs(notableEventNode, reverseList, timestamp, src, port)#开始遍历
        else:
            print("The attacker cannot have access level {} at host {}".format(accessLevel, src))

    def find_node(self, dst, accessLevel):
        for i in self.graph.nodes:
            if i.type == 'state' and i.hostname == dst and i.accessLevel == accessLevel:
                return i

    def print_path(self, list):
        print("Entry: {}".format(list[0]))
        for i in list[1:]:
            print(' -> ' + i)
