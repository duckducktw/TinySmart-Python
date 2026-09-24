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

f = open(SO, 'rb')
elf = ELFFile(f)
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
seen = set()
for seg in elf.iter_segments():
    if seg['p_type'] == 'PT_LOAD':
        va, ms = seg['p_vaddr'], seg['p_memsz']
        b = va & ~0xFFF
        e = (va + ms + 0xFFF) & ~0xFFF
        for p in range(b, e, 0x1000):
            if p not in seen:
                uc.mem_map(p, 0x1000, UC_PROT_ALL); seen.add(p)
        uc.mem_write(va, seg.data())
uc.mem_map(STACK, 0x100000, UC_PROT_ALL)
uc.mem_map(HEAP, 0x100000, UC_PROT_ALL)
uc.mem_map(TLS, 0x10000, UC_PROT_ALL)
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS + 0x1000)

RAND = [0x12345678]

EXT = {
    0x52B0: "nop", 0x52C0: "nop", 0x5300+0x10: "nop",   # cxa_finalize/atexit/stack_chk_fail
    0x52D0: "zero", 0x53B0: "zero", 0x5390: "zero", 0x5370: "zero",
    0x5380: "zero", 0x5360: "one",
    0x5340: "strlen", 0x53A0: "strlen",
    0x5410: "rand",
}
RANDV = [0x12345678]


LAST = [0]


INTERNAL = {
    0x52E0: 0x285C, 0x52F0: 0x2874, 0x5300: 0x28A0, 0x5320: 0x3A48,
    0x5330: 0x3E80, 0x5350: 0x2330, 0x53C0: 0x2700, 0x53D0: 0x288C,
    0x53E0: 0x4650, 0x53F0: 0x4CD8, 0x5400: 0x4760, 0x5420: 0x3B1C,
}


def hook(uc_, addr, size, ud):
    LAST[0] = addr
    t = INTERNAL.get(addr)
    if t is not None:
        uc_.reg_write(UC_ARM64_REG_PC, t)
        return
    k = EXT.get(addr)
    if k is None:
        return
    if k == "rand":
        uc_.reg_write(UC_ARM64_REG_X0, RANDV[0])
    elif k == "one":
        uc_.reg_write(UC_ARM64_REG_X0, 1)
    elif k == "strlen":
        p = uc_.reg_read(UC_ARM64_REG_X0)
        n = 0
        try:
            while n < 4096 and uc_.mem_read(p + n, 1) != b"\x00":
                n += 1
        except Exception:
            n = 0
        uc_.reg_write(UC_ARM64_REG_X0, n)
    else:
        uc_.reg_write(UC_ARM64_REG_X0, 0)
    uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))


uc.hook_add(UC_HOOK_CODE, hook)

def call(fn, args, out_len=None):
    sp = STACK + 0x80000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_LR, RET)
    for i, a in enumerate(args):
        uc.reg_write(UC_ARM64_REG_X0 + i, a)
    uc.emu_start(fn, RET, count=3000000)
    return uc.reg_read(UC_ARM64_REG_X0)
def main():
    # init
    print("init:", hex(call(INIT, [0, 0]) & 0xFFFFFFFFFFFFFFFF))
    PLAT=int(sys.argv[3]) if len(sys.argv)>3 else 2
    print("platform:", hex(call(SET_PLAT, [PLAT]) & 0xFFFFFFFFFFFFFFFF))
    code = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x69522671
    p = HEAP + 0x1000
    uc.mem_write(p, struct.pack('<I', code))
    print("set_ble_code:", hex(call(SET_CODE, [p]) & 0xFFFFFFFFFFFFFFFF))
    # input struct 0x20
    inb = bytearray(0x20)
    inb[0:4] = struct.pack('<I', code)
    # B: 16 zero bytes default
    B = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else b'\x00' * 16
    inb[4:4 + len(B)] = B
    inb[0x14:0x16] = B[0x10:0x12] if len(B) >= 0x12 else b'\x00\x00'
    inb[0x19] = 0
    inb[0x1a] = 0
    inb[0x1b] = 0
    inb[0x1c:0x20] = struct.pack('<I', 0)
    pin = HEAP + 0x2000
    uc.mem_write(pin, bytes(inb))
    pout = HEAP + 0x3000
    uc.mem_write(pout, b'\x00' * 64)
    try:
        r = call(ENCODER, [pin, pout])
    except Exception as e:
        print("CRASH at", hex(LAST[0]), e)
        import subprocess
        print(subprocess.run(['llvm-objdump-21', '-d', '--start-address=%d' % max(0, LAST[0] - 0x20),
                              '--stop-address=%d' % (LAST[0] + 0x20), SO],
                             capture_output=True, text=True).stdout)
        return
    print("ret:", hex(r & 0xFFFFFFFFFFFFFFFF))
    print("out:", uc.mem_read(pout, 40).hex())

if __name__ == '__main__':
    main()
