from TraceSnapshot import *
class AnalyseEngine:
    def __init__(self):
        pass

    def LoadDumpFile(self, path: str) -> TraceSnapshot:
        with open(path,'r') as file:
            lines = file.readlines()
            return TraceSnapshot(lines)
    def show(self, trace: TraceSnapshot):
        pass
