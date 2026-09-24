#!/usr/bin/env python3
"""掃 SET_PLAT，印出 decoder 用的 type 表與 manufacturerIds 表。"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fastlink_emu as FL

plat = int(sys.argv[1])
FL.call(FL.INIT, [0, 0])
FL.call(FL.SET_PLAT, [plat])
p = FL.HEAP + 0x1000
FL.uc.mem_write(p, struct.pack('<I', 0x<BLE_CODE_HEX>))
FL.call(FL.SET_CODE, [p])

def ptr(off):
    try:
        return struct.unpack('<Q', FL.uc.mem_read(0xd000 + off, 8))[0]
    except Exception:
        return 0

tab = ptr(0x738)
t = FL.uc.mem_read(tab, 8).hex() if tab else 'none'
mi = ptr(0x728)
m = FL.uc.mem_read(mi, 4).hex() if mi else 'none'
rv = ptr(0x730)
r = FL.uc.mem_read(rv, 4).hex() if rv else 'none'
print(f"plat={plat} type_tab={t} manufIds={m} revIds={r}")
