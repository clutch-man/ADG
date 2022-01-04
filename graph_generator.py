# Generates an attack graph of state nodes and vulnerability nodes 

import networkx as nx
from input_parser import Parser
from state_node import StateNode
from matplotlib import pyplot as plt

class GraphGenerator(object):

    def __init__(self, startNodeSet, adjList, vulnDict, defDict, portDict,name):

        self.startNodeSet = startNodeSet
        self.adjList = adjList
        self.vulnDict = vulnDict
        self.defDict = defDict
        self.portDict = portDict
        self.name = name
        '''
        输入:开始主机节点集合startNodeSet,可达性集合reachSet,漏洞字典vulnDict,端口字典portDict
        输出：攻击图G
        '''

    def returnaccess(self):
        for state in self.startNodeSet:
            if state.hostname == self.name:
                return state.accessLevel

    
    # 需要与网络拓扑连接
    '''
    返回主机对应的可达性集合
    '''
    def get_reachable(self, hostname):
        reachableSet = self.adjList[hostname]
        return reachableSet

    '''
    返回主机和端口在漏洞字典中映射的漏洞
    '''
    def get_vulnerabilities(self, host, port):
        if (host, port) not in self.vulnDict:
            return None
        return self.vulnDict[(host, port)]

    def get_defense(self,vulID):
        defenseSet = self.defDict[vulID]
        return defenseSet

    '''
    如果漏洞节点的访问向量为Network，那么当前权限等级改为漏洞节点的权限等级，
    如果访问向量为Local，且当前权限等级小于漏洞洞节点的，那么返回漏洞节点的权限等级，否则权限等级不变
    '''
    def get_access_granted(self, vulnerabilityNode, currAccessLevel):
        if vulnerabilityNode.accessVector == 'Network':#accessVector有’Network’与’Local’两类
            return vulnerabilityNode.accessLevel
        elif vulnerabilityNode.accessVector == 'Local':
            if currAccessLevel < vulnerabilityNode.accessLevel:
                return vulnerabilityNode.accessLevel
            else:
                return currAccessLevel

    '''
    攻击图生成算法及可视化
    '''
    def generate_graph(self):
        DG = nx.DiGraph()#创建有向图
        stateset = []
        vulset = []
        defset=[]
        list1 = []
        list2 = []

        # 为开始节点添加漏洞
        for startNode in self.startNodeSet:
            startNodePorts = self.portDict[startNode.hostname]#获取所有可入主机节点的端口
            for port in startNodePorts:
                vulnerabilitySet = self.get_vulnerabilities(startNode.hostname, port)#找到漏洞字典中（可入节点主机名，端口）对应的完整漏洞信息
                if not vulnerabilitySet:
                    continue
                for vulnerabilityNode in vulnerabilitySet:
                    vulnerabilityNode.entry = True#把可入性改为true
                    if vulnerabilityNode.requiredPrivilege == 0:#如果漏洞节点的需求权限为0，则可入节点获得漏洞节点的权限等级。
                        startNode.accessLevel = vulnerabilityNode.accessLevel

                        if not DG.has_node(vulnerabilityNode):
                            DG.add_node(vulnerabilityNode)
                            '''
                            添加漏洞节点
                            '''
                            list1.append(vulnerabilityNode)#list1添加漏洞节点
                            list2.append(vulnerabilityNode.vulnerabilityName)#list2添加漏洞名
                            # if vulnerabilityNode.type=='vuln':
                            #     shape_map.append('d')
                            # else:
                            #     shape_map.append('o')

                        if not DG.has_node(startNode):
                            DG.add_node(startNode)
                            '''
                            添加可入节点
                            '''
                            list1.append(startNode)#list1添加可入节点
                            list2.append(startNode.hostname)#list2添加可入主机名
                            # if startNode.type=='vuln':
                            #     shape_map.append('d')
                            # else:
                            #     shape_map.append('o')


                        DG.add_edge(vulnerabilityNode, startNode)

                        '''
                        可入节点和漏洞节点之间添加边关系
                        '''
                    defenseSet = self.get_defense(vulnerabilityNode.vulnerabilityName)

                    for defenseNode in defenseSet:
                        if defenseNode.vulID == vulnerabilityNode.vulnerabilityName:
                            DG.add_node(defenseNode)
                            DG.add_edge(vulnerabilityNode,defenseNode)
                        # print("Added edge from {} to {}".format(vulnerabilityNode.to_string(), startNode.to_string()))

        stateNodeSet = self.startNodeSet#可入节点集存入状态节点集中
        newStateNodes = set()#新状态节点集

        while stateNodeSet:
            # 遍历每个状态节点的可到达节点集
            for index, stateNode in enumerate(stateNodeSet):

                # print("State node: {}".format(stateNode.to_string()))

                host = stateNode.hostname
                currAccessLevel = stateNode.accessLevel#此时的权限等级=状态节点（可入节点）获得漏洞节点的权限等级
                reachableSet = self.get_reachable(host)
                
                # reachable是一个元组（主机名、端口）
                for reachable in reachableSet:
                    # print("Host {} is reachable to host {}, port {}".format(host, reachable[0], reachable[1]))
                    vulnerablitySet = self.get_vulnerabilities(reachable[0], reachable[1])#返回可达主机和端口在漏洞字典中映射的漏洞

                    if not vulnerablitySet: # No vulnerabilities associated
                        continue 

                    # 添加每个漏洞节点作为状态节点的子节点，如果：
                    # 1) 足够的特权级别
                    # 2) 可访问与该漏洞关联的端口
                    for vulnerabilityNode in vulnerablitySet:
                        # print("Reachable node {} has vulnerability {}".format(reachable, vulnerabilityNode.to_string()))
                        if (currAccessLevel >= vulnerabilityNode.requiredPrivilege) and not (vulnerabilityNode.accessVector == 'Local' and not host == reachable[0]):
                        #如果当前权限等级大于等于漏洞节点的需求权限等级，而且漏洞节点的权限向量不是本地Local，主机名是当前主机名，则进行以下操作。
                            if not DG.has_node(vulnerabilityNode):
                                DG.add_node(vulnerabilityNode)#添加漏洞节点
                                list1.append(vulnerabilityNode)
                                list2.append(vulnerabilityNode.vulnerabilityName)
                                # if vulnerabilityNode.type=='vuln':
                                #     shape_map.append('d')
                                # else:
                                #     shape_map.append('o')

                            if not DG.has_node(stateNode):
                                DG.add_node(stateNode)#添加状态节点
                                list1.append(stateNode)
                                list2.append(stateNode.hostname)
                                # if stateNode.type=='vuln':
                                #     shape_map.append('d')
                                # else:
                                #     shape_map.append('o')


                            if not DG.has_edge(vulnerabilityNode, stateNode) and not DG.has_edge(stateNode, vulnerabilityNode):
                                # print("No edge from {} to {}".format(vulnerabilityNode.to_string(), stateNode.to_string()))
                                DG.add_edge(stateNode, vulnerabilityNode)#状态节点和漏洞节点添加边关系

                            defenseSet = self.get_defense(vulnerabilityNode.vulnerabilityName)

                            for defenseNode in defenseSet:
                                if defenseNode.vulID == vulnerabilityNode.vulnerabilityName:
                                    DG.add_node(defenseNode)
                                    DG.add_edge(vulnerabilityNode,defenseNode)

                                # print("Added edge from {} to {}".format(stateNode.to_string(), vulnerabilityNode.to_string()))
                            
                            newAccessLevel = self.get_access_granted(vulnerabilityNode, currAccessLevel)#更新当前权限等级
                            vulnerableNode = StateNode(reachable[0], newAccessLevel)#以可到达的主机名和新的权限等级创建新的状态节点（vulnerableNode，易受攻击节点）
                            if not DG.has_node(vulnerableNode):
                                newStateNodes.add(vulnerableNode)
                                list1.append(vulnerableNode)
                                list2.append(vulnerableNode.hostname)
                                # if vulnerableNode.type=='vuln':
                                #     shape_map.append('d')
                                #
                                # else:
                                #     shape_map.append('o')


                                # print("Adding {} to newStateNodes".format(vulnerableNode.to_string()))
                            if not DG.has_edge(vulnerabilityNode, vulnerableNode):
                                DG.add_edge(vulnerabilityNode, vulnerableNode)

                                # print("Added edge from {} to {}".format(vulnerabilityNode.to_string(), vulnerableNode.to_string()))

                if index == len(stateNodeSet) - 1:#节点遍历完后，再把刚刚添加的新状态节点再次以以上的规则遍历，直至遍历完所有的状态节点
                    stateNodeSet = newStateNodes
                    newStateNodes = set()

        # pos = nx.spring_layout(DG)
        # nx.draw_networkx_nodes(DG, pos)
        # nx.draw_networkx_edges(DG, pos)
        # plt.show()



        pos = nx.spring_layout(DG)#networkx软件包的弹性布局管理器spring_layout，创建以节点为键位置为值的字典pos
        for node in DG.nodes:

            if hasattr(node, 'type') == False:
                defset.append(node)
            else:
                if node.type == 'state':
                    stateset.append(node)
                if node.type == 'vuln':
                    vulset.append(node)
        #nx.draw(DG, pos)
        #nx.draw(DG,pos)
        nx.draw_networkx_nodes(DG, pos=pos,nodelist=stateset,node_shape='o')#绘制有向图的状态节点
        nx.draw_networkx_nodes(DG, pos=pos,nodelist=vulset,node_shape='^')#绘制有向图的漏洞节点
        nx.draw_networkx_nodes(DG, pos=pos,nodelist=defset,node_shape='s')#绘制有向图的防御节点
        nx.draw_networkx_labels(DG, pos)#绘制有向图的边
        nx.draw_networkx_edges(DG, pos)#绘制节点标签
        #nx.draw_networkx_edge_labels(DG, pos, edge_labels=None, label_pos=0.5)给有向边添加标签（权值）

        nx.write_graphml(DG, "攻击图.graphml")#生成攻击图的xml形式文件
        #nx.write_gexf(DG, "攻击图.gexf")生成攻击图的xml形式文件

        plt.rcParams['font.sans-serif']=['SimHei']
        plt.rcParams['axes.unicode_minus'] = False


        plt.tight_layout(pad=0.4, w_pad=0.5, h_pad=1.0)#自动调整子图参数，使之填充整个图像区域

        #matplotlib绘图库，将攻击图显示并保存在项目文件夹下
        plt.savefig('gongjitu.png')#savefig保存攻击图


        plt.show()#show函数显示攻击图

        statedict = {}
        vulndict = {}

        for snode in list1:
            if snode.type == 'state':
                statedict[snode.hostname] = 0
            if snode.type == 'vuln':
                vulndict[snode.vulnerabilityName] = 0

        return DG,statedict,vulndict
