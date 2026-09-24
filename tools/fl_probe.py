#!/usr/bin/env python3
"""Tool2 encoder 可調參數探針：測 rand() 是否影響輸出、掃 B/type/flags/plat。
用法:
  python3 fl_probe.py rand           # 固定 B，變動 RANDV 看 body 是否改變
  python3 fl_probe.py sweep          # 掃 type / flags / platform
  python3 fl_probe.py B <hexB> [type] [fl0 fl1 fl2] [plat]
"""
import struct, sys
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile

SO = '/tmp/tsx/lib/arm64-v8a/libflashsmartencode.so'
ENCODER = 0x28a0
INIT = 0x2700
SET_PLAT = 0x288c
SET_CODE = 0x285c
STACK = 0x10000000
HEAP = 0x30000000
TLS = 0x40000000
RET = 0x0BADF00D

f = open(SO, 'rb'); elf = ELFFile(f)
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
seen = set()
for seg in elf.iter_segments():
    if seg['p_type'] == 'PT_LOAD':
        va, ms = seg['p_vaddr'], seg['p_memsz']
        b = va & ~0xFFF; e = (va + ms + 0xFFF) & ~0xFFF
        for p in range(b, e, 0x1000):
            if p not in seen:
                uc.mem_map(p, 0x1000, UC_PROT_ALL); seen.add(p)
        uc.mem_write(va, seg.data())
uc.mem_map(STACK, 0x100000, UC_PROT_ALL)
uc.mem_map(HEAP, 0x100000, UC_PROT_ALL)
uc.mem_map(TLS, 0x10000, UC_PROT_ALL)
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS + 0x1000)

EXT = {
    0x52B0: "nop", 0x52C0: "nop", 0x5310: "nop",
    0x52D0: "zero", 0x53B0: "zero", 0x5390: "zero", 0x5370: "zero",
    0x5380: "zero", 0x5360: "one",
    0x5340: "strlen", 0x53A0: "strlen", 0x5410: "rand",
}
INTERNAL = {
    0x52E0: 0x285C, 0x52F0: 0x2874, 0x5300: 0x28A0, 0x5320: 0x3A48,
    0x5330: 0x3E80, 0x5350: 0x2330, 0x53C0: 0x2700, 0x53D0: 0x288C,
    0x53E0: 0x4650, 0x53F0: 0x4CD8, 0x5400: 0x4760, 0x5420: 0x3B1C,
}
STATE = {"rand": 0x12345678, "rand_calls": 0, "last": 0}

def hook(uc_, addr, size, ud):
    STATE["last"] = addr
    t = INTERNAL.get(addr)
    if t is not None:
        uc_.reg_write(UC_ARM64_REG_PC, t); return
    k = EXT.get(addr)
    if k is None:
        return
    if k == "rand":
        STATE["rand_calls"] += 1
        uc_.reg_write(UC_ARM64_REG_X0, STATE["rand"] & 0x7FFFFFFF)
    elif k == "one":
        uc_.reg_write(UC_ARM64_REG_X0, 1)
    elif k == "strlen":
        p = uc_.reg_read(UC_ARM64_REG_X0); n = 0
        try:
            while n < 4096 and uc_.mem_read(p + n, 1) != b"\x00": n += 1
        except Exception: n = 0
        uc_.reg_write(UC_ARM64_REG_X0, n)
    else:
        uc_.reg_write(UC_ARM64_REG_X0, 0)
    uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

uc.hook_add(UC_HOOK_CODE, hook)

def call(fn, args):
    sp = STACK + 0x80000
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_LR, RET)
    for i, a in enumerate(args):
        uc.reg_write(UC_ARM64_REG_X0 + i, a)
    uc.emu_start(fn, RET, count=3000000)
    return uc.reg_read(UC_ARM64_REG_X0)

def init(code, plat=2):
    call(INIT, [0, 0]); call(SET_PLAT, [plat])
    p = HEAP + 0x1000; uc.mem_write(p, struct.pack('<I', code))
    call(SET_CODE, [p])

def encode(code, B, typ=0, flags=(0, 0, 0), plat=2):
    init(code, plat)
    STATE["rand_calls"] = 0
    inb = bytearray(0x20)
    inb[0:4] = struct.pack('<I', code)
    inb[4:4 + len(B)] = B[:0x10]
    inb[0x14:0x16] = B[0x10:0x12] if len(B) >= 0x12 else b'\x00\x00'
    inb[0x19], inb[0x1a], inb[0x1b] = flags
    inb[0x1c:0x20] = struct.pack('<I', typ)
    pin = HEAP + 0x2000; uc.mem_write(pin, bytes(inb))
    pout = HEAP + 0x3000; uc.mem_write(pout, b'\x00' * 96)
    call(ENCODER, [pin, pout])
    return uc.mem_read(pout, 40), STATE["rand_calls"]

CODE = 0x<BLE_CODE_HEX>

def body(out):
    return out[15:39].hex()

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'rand'
    if mode == 'rand':
        B = b'\x00' * 16
        print("B=zeros, type=0, flags=0, plat=2；只變 RANDV")
        for rv in (0x0, 0x1, 0x12345678, 0xDEADBEEF, 0x7FFFFFFF, 0x5A5A5A5A):
            STATE["rand"] = rv
            out, rc = encode(CODE, B)
            print(f"  RANDV={rv:#010x} rand_calls={rc} body={body(out)}")
    elif mode == 'sweep':
        B = b'\x00' * 16
        for plat in (0, 1, 2, 3):
            for typ in (0, 1, 2):
                out, rc = encode(CODE, B, typ=typ, plat=plat)
                print(f"  plat={plat} type={typ} rand_calls={rc} out={out.hex()}")
    elif mode == 'B':
        B = bytes.fromhex(sys.argv[2])
        typ = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
        flags = tuple(int(x, 0) for x in sys.argv[4:7]) if len(sys.argv) > 6 else (0, 0, 0)
        plat = int(sys.argv[7]) if len(sys.argv) > 7 else 2
        out, rc = encode(CODE, B, typ=typ, flags=flags, plat=plat)
        print(f"  B={B.hex()} type={typ} flags={flags} plat={plat} rand_calls={rc}")
        print(f"  out={out.hex()}")
        print(f"  body={body(out)}")
