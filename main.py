from event_finder import EventFinder
from graph_generator import GraphGenerator
from graph_traverser import GraphTraverser
from input_parser import Parser
from possibilities import Possibilities
from state_node import StateNode

parser = Parser()#创建input_parser的对象
startNodeSet,name = parser.parseStartNodes()#手动输入可入节点数量和名称，得到存放主机名和访问级别为0的可入节点集合、输入的第一个可入节点名
adjList = parser.parseReachability()#输入可达性文件路径，得到可达性字典：源主机映射到（可达主机，端口）
vulnDict, portDict = parser.parseVulnerabilities()#输入漏洞文件路径，获得漏洞字典：主机名映射到完整的漏洞信息，获得端口字典：主机对应漏洞端口号
eventMapping = parser.parseEventMapping()#输入漏洞-事件文件，获得漏洞-事件字典。
eventSet = EventFinder('admin', '123456789')#创建事件查找对象。其中的方法用于检查splunk事件集中是否存在漏洞事件
defDict = parser.parseDefense()
# 生成攻击图
graphGenerator = GraphGenerator(startNodeSet, adjList, vulnDict, defDict, portDict,name)#输入所有已知参数，创建对象
DG,statedict,vulndict = graphGenerator.generate_graph()#获取生成的攻击图DG和状态节点名、漏洞节点名

access = graphGenerator.returnaccess()#返回可入节点的权限等级(2高/1低/0无)

timestamp, src, dst, port, description, accessLevel = parser.parseNotableEvent()#获得手动输入的值得注意的事件和攻击者权限（none/user/root）

graphTraverser = GraphTraverser(DG, eventSet, eventMapping, portDict.keys())
eventSequence = graphTraverser.start_traversal(timestamp, src, dst, port, description, accessLevel)#开始深度优先遍历，寻找前驱节点，生成事件列表


# 输出可能性
crownJewelSet = parser.parseCrownJewels()#获得目标状态主机节点集
possibilitiesGenerator = Possibilities()

notableEventStateNode = StateNode(name, access)#获得输入的第一个可入主机节点

possibilitiesGenerator.printPossiblePaths(DG, notableEventStateNode, crownJewelSet,statedict,vulndict)#打印到目标主机的最短路径的序号、利用次数最多的漏洞以及被攻击次数最多的主机
