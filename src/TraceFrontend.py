class TraceFrontend:
    def __init__(self):
        pass
    def toDumpFile(self, path:str, data:str):
        with open(path, "w") as file:
            file.write(data)