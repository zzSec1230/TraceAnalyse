import dataclasses
import os

import lief
from typing import List, Optional
from enum import Enum
from typing import Dict, List, Tuple, Optional

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


class MachoLoader():

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
        binary: lief.MachO.Binary = lief.parse(module_file)
        segment_addresses = [t.virtual_address for t in binary.segments]
        #image base是MachO文件准备load到的内存地址
        image_base = aligned(min(segment_addresses), 1024)
        #计算和指定的加载地址之间的偏移
        module_base_offset = module_base - image_base
        size = self._map_segments(binary, module_base_offset)
        #获得所有的符号信息
        symbols = self._load_symbols(binary, module_base)
        lazy_bindings = self._process_relocation(binary, module_base, symbols)
        init_array = self._get_init_array(binary, module_base)
        return Module(
            base=module_base + image_base,
            size=size - image_base,
            name=module_name,
            symbols=symbols,
            init_array=init_array,
            image_base=image_base,
            lazy_bindings=lazy_bindings,
            binary=binary,
        )

    def _get_init_array(self, binary: lief.MachO.Binary, module_base: int):
        """Get initialization functions in section `__mod_init_func`."""
        section = binary.get_section("__mod_init_func")
        if not section:
            return []

        begin = module_base + section.virtual_address
        end = begin + section.size
        #values = self.emu.read_array(begin, end)

        return [addr for addr in values if addr]

    #处理重定位
    def _process_relocation(
        self,
        binary: lief.MachO.Binary,
        module_base: int,
        symbols: List[Symbol],
    ):
        """Process relocations base on relocation table and symbol references."""
        blocks: List[Tuple[int, int]] = []

        begin = None
        end = None

        # Merge relocation records into blocks
        for segment in binary.segments:
            for relocation in segment.relocations:
                if relocation.type != ARM64_RELOCATION.SUBTRACTOR:
                    continue

                address = module_base + relocation.address

                if not begin:
                    begin = address

                if end and address != end:
                    blocks.append((begin, end))
                    begin = address

                end = address + self.emu.arch.addr_size

        # Read and write as blocks
        for begin, end in blocks:
            values = self.emu.read_array(begin, end)
            values = map(lambda v: module_base + v, values)

            self.emu.write_array(begin, values)

        return self._process_symbol_relocation(binary, module_base, symbols)

    def _map_segments(self, binary: lief.MachO.Binary, module_base_offset: int) -> int:
        """Map all segments into memory."""
        boundary = 0

        for segment in binary.segments:
            if not segment.virtual_size:
                continue
            #修正segment的加载地址
            seg_addr = module_base_offset + segment.virtual_address
            #对其加载地址
            map_addr = aligned(seg_addr, 1024) - (1024 if seg_addr % 1024 else 0)
            map_size = aligned(seg_addr - map_addr + segment.virtual_size, 1024)

            # self.emu.uc.mem_map(map_addr, map_size)
            # self.emu.uc.mem_write(
            #     seg_addr,
            #     bytes(segment.content),
            # )

            boundary = max(boundary, map_addr + map_size)

        return boundary - module_base
    def get_lazy_bindings(self):
        return ["test"]
    def _load_symbols(
        self,
        binary: lief.MachO.Binary,
        module_base_offset: int,
    ) -> List[Symbol]:
        """Get all symbols in the module."""
        symbols = []

        lazy_bindings = self.get_lazy_bindings()
        lazy_binding_set = set()
        # 遍历symbol table
        for symbol in binary.symbols:
            if symbol.value:
                symbol_name = str(symbol.name)
                symbol_address = module_base_offset + symbol.value

                # binding_name = symbol_name.replace("$VARIANT$armv81", "")

                # Lazy bind 处理Lazy bind的逻辑，暂时不管
                # if lazy_bindings.get(binding_name):
                #     # Avoid duplicate bind for special case like xx$VARIANT$armv81
                #     if binding_name in lazy_binding_set and binding_name == symbol_name:
                #         continue
                #
                #     for module, binding in lazy_bindings[binding_name]:
                #         reloc_addr = symbol_address
                #
                #         if reloc_addr:
                #             addr = module.base - module.image_base + binding.address
                #
                #             value = reloc_addr + binding.addend
                #             value &= 0xFFFFFFFFFFFFFFFF
                #
                #             #self.emu.write_pointer(addr, value)
                #
                #     lazy_binding_set.add(binding_name)

                symbol_struct = Symbol(
                    address=symbol_address,
                    name=symbol_name,
                )
                symbols.append(symbol_struct)

        return symbols