import struct

class MachoFile(object):
    def __init__(self, filename):
        self.filename = filename
        self.fp = open(filename, 'rb')

    def read_values(self,offset,blocklen,count):
        self.fp.seek(offset)
        data = self.fp.read(count * blocklen)
        values = struct.unpack(f'<{count}I', data)
        return list(values)

