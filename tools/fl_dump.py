#!/usr/bin/env python3
"""在模擬器內 dump 記憶體，尋找加密前明文緩衝 / 金鑰流。
做法：跑兩個 encode（B=0 與 B=1），diff heap/stack，找出結構化緩衝。
"""
import struct, sys, importlib.util

spec = importlib.util.spec_from_file_location("flp", "fl_probe.py")
flp = importlib.util.module_from_spec(spec); spec.loader.exec_module(flp)

uc = flp.uc
HEAP, STACK = flp.HEAP, flp.STACK

def snap():
    return uc.mem_read(HEAP, 0x100000) + uc.mem_read(STACK, 0x100000)

o0, _ = flp.encode(flp.CODE, bytes(16))
s0 = snap()
B1 = bytearray(16); B1[0] = 1
o1, _ = flp.encode(flp.CODE, bytes(B1))
s1 = snap()

body0 = o0[15:39]
print("body0 =", body0.hex())
print("body1 =", o1[15:39].hex())

# 找出 body 在 mem 的位址（若存在，可能是輸出前的明文/中間值）
for name, s in (("after-enc0", s0),):
    i = s.find(body0)
    print(f"body0 出現於 {name} offset={i:#x}" + (f" (heap {i:#x})" if i>=0 else ""))
    j = 0
    while True:
        j = s.find(body0, j+1)
        if j < 0: break
        print(f"   also @ {j:#x}")

# diff 區域
print("\n== mem diff（B[0]: 0->1）區段 ==")
regions = []
in_d = False; st = 0
for k in range(min(len(s0), len(s1))):
    d = s0[k] != s1[k]
    if d and not in_d: in_d = True; st = k
    elif not d and in_d:
        in_d = False
        if k - st >= 1: regions.append((st, k))
for st, en in regions[:40]:
    seg = s0[st:en]
    where = "HEAP" if st < 0x100000 else "STACK"
    off = st if st < 0x100000 else st - 0x100000
    print(f"  {where}+{off:#07x}..{en-st:>3}B  old={seg[:48].hex()}")
