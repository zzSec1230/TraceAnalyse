from .InstructionRecord import *

class TraceSnapshot:
    def __init__(self,engine,lines):
        # TraceRecord数组
        self.records = []
        self.engine = engine
        basicInfo = json.loads(lines[0])
        # 第一行是modulebase
        self.modulebase = basicInfo["modulebase"]
        prev_record = None
        for line in lines[1:]:
            record = InstructionRecord(line,prev_record)
            self.records.append(record)
            prev_record = record

    def show(self):
        for record in self.records:
            line_str = ""
            show_format = "%p"
            address = record.address
            address_symbol = self.engine.getSymbolFromAddress(address)
            mnemonic = record.mnemonic
            opStr = record.opStr
            readRegs_dict = record.getReadRegsAndValue()
            writtenRegs_dict = record.getWriteRegsAndValue()
            symbol = record.symbol
            print(f"{address}!{address_symbol} {mnemonic} {opStr} r:{readRegs_dict} w:{writtenRegs_dict} extra:{symbol}" )

