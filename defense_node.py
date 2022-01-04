class DefenseNode(object):
    def __init__(self, vulID, defID):
        self.vulID = vulID
        self.defID = defID

    def to_string(self):
        return "({}, {}, {})".format(self.vulID, self.defID)

    def __eq__(self, other):
        return self.vulID == other.vulID and self.defID == other.defID

    def __hash__(self):
        return hash(('vulID', self.vulID, 'defID', self.defID))

    def __str__(self):
        return self.defID
