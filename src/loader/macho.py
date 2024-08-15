import dataclasses
import os
from capstone import *
import lief
from typing import List, Optional
from enum import Enum
from typing import Dict, List, Tuple, Optional

import utils.FileUtil
from utils.DebugUtil import dbg_print
from utils.DisamUtil import get_mem_disp
from utils.const import MODULE_ADDRESS
from utils.utils import aligned
from lief.MachO import ARM64_RELOCATION

class SymbolType(Enum):
    FUNC = 1
    OTHER = 2

@dataclasses.dataclass
class Symbol:
    address: int
    name: str
    type: Optional[SymbolType] = None

#新语法 类属性的类型注解是在 Python 3.6 引入的一种语法
#即声明类的属性，以及属性的类型
class Binding:
    symbol: str
    address: int
    addend: int


class Module:
    def __init__(self,base,
                 size,
                 name,
                 symbols: List[Symbol], #不用Optional语法，应该是不能传None值的
                 init_array: Optional[List[int]] = None, #Optional是参数可选类型，虽然这里是可选List[int],但是默认也可以是None
                 image_base: Optional[int] = None,
                 lazy_bindings: Optional[List[Binding]] = None,
                 binary: Optional[lief.MachO.Binary] = None):
        self.base = base
        self.size = size
        self.name = name
        self.symbols = symbols
        self.init_array = init_array
        self.image_base = image_base
        self.lazy_bindings = lazy_bindings
        self.binary = binary

    #binary就是一个lief.MachO.Binary ，这里是一个利用lief获取MachO信息的例子
    def get_segment_vmaddrs(self):
        segment_addresses = [t.virtual_address for t in self.binary.segments]
        return segment_addresses
    def getSymbolFromAddress(self, address):
        for symbol in self.symbols:
            if symbol.address == address:
                return symbol


class MachoLoader():
    #装在MachO文件
    def load(
        self,
        module_file: str,
        module_base: int, # module_base是准备加载到的地址
        image_base: int = MODULE_ADDRESS, #image_base是MachO开始准备加载到的地址
        trace_symbol_calls: bool = False,
    ) -> Module:
        """Load Mach-O executable file from path."""
        module_name = os.path.basename(module_file)
        # 后续
        self.binary: lief.MachO.Binary = lief.parse(module_file)
        self.machofile : utils.FileUtil.MachoFile = utils.FileUtil.MachoFile(module_file)
        segment_addresses = [t.virtual_address for t in self.binary.segments]
        #image base是MachO文件准备load到的内存地址，取所有segment要加载的最小值
        image_base = aligned(min(segment_addresses), 1024)
        #计算和指定的加载地址之间的偏移 即slide
        #如果module_base给的是0 那么就按image_base加载
        if module_base == 0:
            module_base = image_base
        module_base_offset = module_base - image_base
        self.slide = module_base_offset
        size = self._map_segments(self.binary, module_base_offset)
        #获得所有的符号信息
        self.symbols = self._load_symbols(self.binary, module_base)

        # 获取Stubs的映射表
        stubsMap  = self._getStubsMap()
        #lazy_bindings = self._process_relocation(binary, module_base, symbols)
        #init_array = self._get_init_array(binary, module_base)
        return Module(
            base=module_base + image_base,
            size=size - image_base,
            name=module_name,
            symbols=self.symbols,
            init_array=None,
            image_base=image_base,
            lazy_bindings=None,
            binary=self.binary,
        )
    def _getStubsMap(self):
        #先得到Stubs的section
        stubs_section = self.binary.get_section("__stubs")
        #先建立Stubs到其跳转地址的映射表
        # 获取stubs_section的起始地址
        stubs_section_start = stubs_section.virtual_address + self.slide
        stubs_map = {}
        if stubs_section is not None:
            code = bytearray(stubs_section.content)
            cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)  # 根据实际架构选择
            cs.detail = True
            # 反汇编并输出指令
            adrp_value = None
            ins_count = 0
            final_address = None
            instruction_address = None
            for instruction in cs.disasm(code, stubs_section_start):
                ins_count += 1
                if instruction.mnemonic == "adrp":
                    # 计算基地址
                    adrp_value = (instruction.operands[1].imm & 0xFFFFFFFFF000)
                    instruction_address = instruction.address
                elif instruction.mnemonic == "ldr" and adrp_value is not None:
                    pass
                    # 计算最终地址
                    offset = get_mem_disp(instruction.op_str)
                    final_address = adrp_value + offset
                print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
                #三组指令记一个Stubs
                if ins_count%3 == 0:
                    stubs_map[instruction_address] = final_address
        else:
            print("Stubs section not found")
        # 获取got section 和 la_symbol_ptr
        got_section = self.binary.get_section("__got")
        got_reserved1 = got_section.reserved1
        got_section_vaddr = got_section.virtual_address
        got_section_size = got_section.size
        la_ptr_section = self.binary.get_section("__la_symbol_ptr")
        la_reserved1 = la_ptr_section.reserved1
        la_section_vaddr = la_ptr_section.virtual_address
        la_section_size = la_ptr_section.size
        indirect_symbol_offset = self.binary.dynamic_symbol_command.indirect_symbol_offset
        indirect_symbol_nb = self.binary.dynamic_symbol_command.nb_indirect_symbols
        indirect_symbol_data = self.machofile.read_values(indirect_symbol_offset,4,indirect_symbol_nb)
        dbg_print(indirect_symbol_data)
        for (key,value) in stubs_map.items():
            got_section_offset = value - got_section_vaddr
            la_section_offset = value - la_section_vaddr
            if got_section_offset >= 0 and got_section_offset < got_section_size:
                symbol_index = indirect_symbol_data[int(got_section_offset/8) + got_reserved1]
            elif la_section_offset >= 0 and la_section_offset < la_section_size:
                symbol_index = indirect_symbol_data[int(la_section_offset/8) + la_reserved1]
            else:
                symbol_index = -1
            # 重新桥接
            if symbol_index == -1:
                stubs_map[key] = None
            else:
                stubs_map[key] = self.symbols[symbol_index].name
        dbg_print(stubs_map)




    def _map_segments(self, binary: lief.MachO.Binary, module_base_offset: int) -> int:
        """Map all segments into memory."""
        boundary = 0

        for segment in binary.segments:
            if not segment.virtual_size:
                continue
            #修正segment的加载地址
            seg_addr = module_base_offset + segment.virtual_address
            #segment的加载地址对齐
            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            #大小对齐
            map_size = aligned(seg_addr - map_addr + segment.virtual_size, 1024)

            # self.emu.uc.mem_map(map_addr, map_size)
            # self.emu.uc.mem_write(
            #     seg_addr,
            #     bytes(segment.content),
            # )
            # 计算最后一个segment被加载到内存中的地方
            boundary = max(boundary, map_addr + map_size)
        # 最后一个segment的末尾 - 加载起始地址就是大小
        return boundary - module_base_offset
    def get_lazy_bindings(self):
        return ["test"]
    def _load_symbols(
        self,
        binary: lief.MachO.Binary,
        module_base_offset: int,
    ) -> List[Symbol]:
        """Get all symbols in the module."""
        symbols = []

        # 遍历symbol table
        for symbol in binary.symbols:
            if symbol.value:
                symbol_name = str(symbol.name)
                # 加上偏移
                symbol_address = self.slide + symbol.value
                symbol_struct = Symbol(
                    address=symbol_address,
                    name=symbol_name,
                )
                symbols.append(symbol_struct)
            else:
                symbol_name = str(symbol.name)
                symbol_address = symbol.value
                symbol_struct = Symbol(
                    address=symbol_address,
                    name=symbol_name,
                )
                symbols.append(symbol_struct)

        return symbols