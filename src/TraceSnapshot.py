from InstructionRecord import *

class TraceSnapshot:
    def __init__(self,lines):
        # TraceRecord数组
        self.records = []
        basicInfo = json.loads(lines[0])
        # 第一行是modulebase
        self.modulebase = basicInfo["modulebase"]
        for line in lines[1:]:
            self.records.append(InstructionRecord(line))

