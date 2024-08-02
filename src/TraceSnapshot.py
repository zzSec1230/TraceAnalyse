from InstructionRecord import *
from AnalyseEngine import *
class TraceSnapshot:
    def __init__(self,engine: AnalyseEngine,lines):
        # TraceRecord数组
        self.records = []
        self.engine = engine
        basicInfo = json.loads(lines[0])
        # 第一行是modulebase
        self.modulebase = basicInfo["modulebase"]
        for line in lines[1:]:
            self.records.append(InstructionRecord(line))

    def show(self):
        for record in self.records:
            line_str = ""
            show_format = "%p"
            address = record.address
            address_symbol = self.engine.getSymbolFromAddress(address)
            opStr = record.opStr

            print(f"{address:#x}!{address_symbol} {opStr} ")

