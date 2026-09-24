import struct, sys, subprocess, json, base64
sys.argv = ['x']
exec(open('/tmp/fl_emu.py').read().split("def main()")[0])

INIT0 = 0x2700
CODEC = 0x285C
SETP = 0x288C

def mk_body(A4: bytes, B: bytes, flags=(0, 0, 0), typ=0, fmt=2, ifmt=0):
    sp = STACK + 0x80000
    # init
    pa = HEAP + 0x4000; pb = HEAP + 0x5000
    uc.mem_write(pa, A4.ljust(4, b'\x00'))
    uc.mem_write(pb, B.ljust(0x20, b'\x00'))
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_LR, RET)
    uc.reg_write(UC_ARM64_REG_X0, 0); uc.reg_write(UC_ARM64_REG_X1, 0)
    uc.reg_write(UC_ARM64_REG_X2, 0); uc.reg_write(UC_ARM64_REG_X3, 0)
    uc.emu_start(INIT0, RET, count=3000000)
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_LR, RET)
    uc.reg_write(UC_ARM64_REG_X0, 2)
    uc.emu_start(SETP, RET, count=100000)
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_LR, RET)
    uc.reg_write(UC_ARM64_REG_X0, pa)
    uc.emu_start(CODEC, RET, count=100000)
    # encoder
    inb = bytearray(0x20)
    inb[0:4] = A4.ljust(4, b'\x00')[:4]
    inb[4:4 + len(B)] = B[:0x10]
    inb[0x14:0x16] = B[0x10:0x12] if len(B) >= 0x12 else b'\x00\x00'
    inb[0x19], inb[0x1a], inb[0x1b] = flags
    inb[0x1c:0x20] = struct.pack('<I', typ)
    pin = HEAP + 0x2000; uc.mem_write(pin, bytes(inb))
    pout = HEAP + 0x3000; uc.mem_write(pout, b'\x00' * 64)
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_LR, RET)
    uc.reg_write(UC_ARM64_REG_X0, pin); uc.reg_write(UC_ARM64_REG_X1, pout)
    uc.emu_start(ENCODER, RET, count=3000000)
    return uc.mem_read(pout, 48)

if __name__ == '__main__':
    ble = bytes.fromhex(sys.argv[1] if len(sys.argv) > 1 else '<BLE_CODE_HEX>')
    for typ in range(0, 10):
        out = mk_body(ble, bytes([0, 2]) + b'\x00' * 8, typ=typ)
        print(f"type=0x{typ:02X}: {out.hex()}")
