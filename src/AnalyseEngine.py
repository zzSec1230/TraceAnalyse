
from .TraceSnapshot import TraceSnapshot


class AnalyseEngine:
    def __init__(self):
        pass

    def LoadDumpFile(self, path: str) -> TraceSnapshot:
        with open(path,'r') as file:
            lines = file.readlines()
            return TraceSnapshot(self,lines)
    def show(self, trace: TraceSnapshot, output_path: str):
        trace.show()

    def getSymbolFromAddress(self,address: str):
        return None
