# {"address": "0x104cec0f0", "next": "0x104cec0f4", "size": 4, "mnemonic": "ldp", "opStr": "x29, x30, [sp, #0x30]",
#  "operands": [{"type": "reg", "value": "fp", "access": "w"}, {"type": "reg", "value": "lr", "access": "w"},
#               {"type": "mem", "value": {"base": "sp", "disp": 48}, "access": "r"}],
#  "regsAccessed": {"read": ["sp"], "written": ["fp", "lr"]}, "regsRead": [], "regsWritten": [], "groups": [],
#  "context": {"pc": "0x104cec0f0", "sp": "0x16b115320", "nzcv": 1610612736, "x0": "0x1dd1a9340", "x1": "0x282ad03c0",
#              "x2": "0x16b115218", "x3": "0x0", "x4": "0x0", "x5": "0x0", "x6": "0x0", "x7": "0x403", "x8": "0x7fffffff",
#              "x9": "0x7fffffff", "x10": "0x2811d1380", "x11": "0x3", "x12": "0x2", "x13": "0x0",
#              "x14": "0xfffffffffffffffe", "x15": "0x1", "x16": "0xffffffffffffffff", "x17": "0x1", "x18": "0x0",
#              "x19": "0x280ac40c0", "x20": "0x10550a1e0", "x21": "0x104cf041c", "x22": "0x105509ba0",
#              "x23": "0x104cf041c", "x24": "0x1dd212908", "x25": "0x0", "x26": "0x1d6340b6c", "x27": "0x280ac40c0",
#              "x28": "0x1", "fp": "0x16b115380", "lr": "0x10d11c00c", "q0": {}, "q1": {}, "q2": {}, "q3": {}, "q4": {},
#              "q5": {}, "q6": {}, "q7": {}, "q8": {}, "q9": {}, "q10": {}, "q11": {}, "q12": {}, "q13": {}, "q14": {},
#              "q15": {}, "q16": {}, "q17": {}, "q18": {}, "q19": {}, "q20": {}, "q21": {}, "q22": {}, "q23": {},
#              "q24": {}, "q25": {}, "q26": {}, "q27": {}, "q28": {}, "q29": {}, "q30": {}, "q31": {},
#              "d0": -7.886303348890616e+303, "d1": 0, "d2": 7.9499288951273454e-275, "d3": 0, "d4": 70, "d5": null,
#              "d6": 215, "d7": 0, "d8": 0, "d9": 0.0000016080749353e-308, "d10": 0.0001022702502693e-308,
#              "d11": 0.000001591496843e-308, "d12": 0, "d13": 0, "d14": 0.0000016080749353e-308,
#              "d15": 0.0001022702502693e-308, "d16": -1.0855813867524649e+251, "d17": 0.000002084565455e-308,
#              "d18": 3.0554698911305689e-152, "d19": 0.000001322084152e-308, "d20": 3.7696966457559071e-175,
#              "d21": 1.0004894955531618e+128, "d22": 9.5944260775693913e+225, "d23": -6.8154492514793903e-236,
#              "d24": -2.1930923744387854e+50, "d25": 0.0002661999889761748, "d26": 0.0000014094978223249855,
#              "d27": 4.8274986342189230e-23, "d28": 4026532.510214844, "d29": 0.017139885549466098, "d30": 0, "d31": 0,
#              "s0": null, "s1": 0, "s2": 3.8204714345426298e-37, "s3": 0, "s4": 0, "s5": 0, "s6": 0, "s7": 0, "s8": 0,
#              "s9": -32, "s10": 7.4505805969238263e-9, "s11": -2, "s12": 0, "s13": 0, "s14": -32,
#              "s15": 7.4505805969238263e-9, "s16": 1.5548730664783592e-21, "s17": -1.3084408235578860e+36,
#              "s18": -8.6088756618229034e-23, "s19": -5.408784745233076e-20, "s20": 4.2151578028428229e+37,
#              "s21": 18362722504671230, "s22": 3.372155249992253e+28, "s23": -7.6784630118876258e-30, "s24": -3715189.5,
#              "s25": 0.6931471824645996, "s26": 0.35632285475730896, "s27": 0.003130804980173707,
#              "s28": 12.920000076293945, "s29": 1.1371190547943115, "s30": 0, "s31": 0}}
import json

class Instruction:
    def __init__(self):
        pass

class InstructionContext:
    def __init__(self):
        pass

class InstructionRecord:
    def __init__(self,record: str,prev_record):
        recordObject = json.loads(record)
        self.record = recordObject
        self.context = self.record["context"]
        self.extra = None
        if "extra" in self.record:
            self.extra = self.record["extra"]

        self.prev_record = prev_record

    # 需要处理w寄存器
    def getRegValue(self,regName: str) -> str:
        if 'w' in regName:
            return hex(int(self.context[regName.replace('w','x')],16) & 0xffffffff)
        return self.context[regName]
    def setRegValue(self, regName: str, value: int):
        if 'w' in regName:
            old_value = int(self.context[regName.replace('w','x')],16)
            new_value = ((old_value >> 32) <<32) | value
            self.context[regName] = hex(new_value)
        self.context[regName] = hex(value)

    @property
    def address(self):
        return self.record["address"]
    #
    # Deduplication by default
    @property
    def regsAccessed(self) -> list:
        regsAccessed = set()
        regsAccessed.add(self.record["regsAccessed"]["read"])
        regsAccessed.add(self.record["regsAccessed"]["written"])
        return list(regsAccessed)

    @property
    def readRegs(self):
        return self.record["regsAccessed"]["read"]

    @property
    def writtenRegs(self):
        return self.record["regsAccessed"]["written"]

    @property
    def mnemonic(self):
        return self.record["mnemonic"]

    @property
    def operands(self):
        return self.record["operands"]

    @property
    def opStr(self):
        return self.record["opStr"]

    @property
    def symbol(self):
        if self.extra is not None:
            return self.extra["symbol"]["name"]
        return None
    # 因为当前的context是指令已经执行结束后得到的，所以假如指令是这种add x8,x8,2 那么此时得到的
    # x8寄存器的值就已经是计算后的值了
    # 所以需要改成从prev_record中获取
    def getReadRegsAndValue(self):
        readRegs = self.readRegs
        reg_dict = {}
        if self.prev_record is not None:
            for reg in readRegs:
                reg_dict[reg] = self.prev_record.getRegValue(reg)
        return reg_dict

    def getWriteRegsAndValue(self):
        writeRegs = self.writtenRegs
        reg_dict = {}
        for reg in writeRegs:
            reg_dict[reg] = self.getRegValue(reg)
        return reg_dict


