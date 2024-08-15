import re


def get_mem_disp(OpStr):
    match = re.search(r'#(?:0x)?([0-9A-Fa-f]+|\d+)', OpStr)
    if match:
        hex_value = match.group(1)
        int_value = int(hex_value, 16)
        return int_value
    else:
        return 0