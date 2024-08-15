from loader.macho import *


if __name__ == '__main__':
    macho_loader = MachoLoader()
    macho_loader.load("/Users/bytedance/ios_reverse/libida64.dylib",0)
