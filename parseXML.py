import xml.sax


class ConfigHandler(xml.sax.ContentHandler):

    def __init__(self):
        self.tag = ""
        self.name = ""
        self.label = ""
        self.content = ""

    # 启动文档
    def startDocument(self):
        print("******解析配置文件开始******")

    # 开始解析xml
    def startElement(self, name, attributes):
        self.tag = name
        if name == "node":
            self.name = attributes["id"]
            print(self.name)
        elif name == "edge":
            #self.name = attributes["id"]
            print(attributes["source"], attributes["target"])
        if name == "data":
            self.label = attributes["key"]
            print(self.label)

    # xml内容事件处理
    def characters(self, content):
        self.content = content

    # 结束解析xml
    def endElement(self, name):
        if name == "data":
            print(self.content)

    # xml结束标签调用
    def endDocument(self):
        print("******配置文件解析结束******")


if __name__ == "__main__":
    # 创建一个 XMLReader
    parser = xml.sax.make_parser()
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)
    # 重写 ContextHandler
    Handler = ConfigHandler()
    parser.setContentHandler(Handler)
    # 解析 xml 这里可以写xml 的具体路径,为了简单放在了同一个文件夹里面了
    parser.parse("攻击图.graphml")
