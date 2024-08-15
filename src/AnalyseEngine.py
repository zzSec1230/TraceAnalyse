from loader.macho import MachoLoader, Module
from .TraceSnapshot import TraceSnapshot


class AnalyseEngine:
    def __init__(self):
        pass

    def LoadModule(self,module_file,module_base) -> Module:
        loader = MachoLoader()
        return loader.load(module_file,module_base)



    def LoadDumpFile(self, path: str) -> TraceSnapshot:
        with open(path,'r') as file:
            lines = file.readlines()
            return TraceSnapshot(self,lines)
    def show(self, trace: TraceSnapshot, output_path: str):
        trace.show()

    def getSymbolFromAddress(self,module: Module,address: int):
        return module.getSymbolFromAddress(address)
