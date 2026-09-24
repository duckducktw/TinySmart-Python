#!/usr/bin/env python3
"""用 .so 的 ble_fast_link_decoder 解密實機 body → 16B 明文。"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fastlink_emu as FL

DECODER = 0x3e80
CODE = 0x<BLE_CODE_HEX>


def setup(platform=2, code=CODE):
    FL.call(FL.INIT, [0, 0])
    FL.call(FL.SET_PLAT, [platform])
    p = FL.HEAP + 0x1000
    FL.uc.mem_write(p, struct.pack('<I', code))
    FL.call(FL.SET_CODE, [p])


def decode(body24, platform=2, code=CODE, randv=0x12345678):
    setup(platform, code)
    FL.RANDV[0] = randv
    pin = FL.HEAP + 0x5000
    FL.uc.mem_write(pin, bytes(body24))
    pout = FL.HEAP + 0x6000
    FL.uc.mem_write(pout, b'\x00' * 64)
    r = FL.call(DECODER, [pin, len(body24), pout])
    return r, bytes(FL.uc.mem_read(pout, 16))


if __name__ == '__main__':
    bodies = [
        '89a5af88921dcd1b87e989105df1511ecd5dc2d98d84cae1',
        '893a2b56c20ecd18871f57404e2cea6a3d9c57170e7d566c',
        '89121168170ccd198702597f2f67dab3780ae9ef87511222',
        '895d0179d4decd1687fc48bfd1aaaf9b12a850f1451450',
        '890c05fbaea0cd1f8794fa2ce0a94f9317f5d01138fd5a28',
        '896f2488a015cd1c87af8922556a9adcd583b9c54011d02d',
    ]
    for h in bodies:
        try:
            r, out = decode(bytes.fromhex(h))
            print(f"ret={hex(r & 0xffffffff)}  {h} -> {out.hex()}")
        except Exception as e:
            print(f"{h} ERR {e}")
