#!/usr/bin/env python3
"""Tool2 (FlashSmart fast-link) 編碼器 — 可重用模組。
用法:
  from fl_encode import encode, ad_payload
  out = encode(head4, data16, typ=0, randv=0x...)     # 40B
  ad  = ad_payload(head4, data16)                     # 31B legacy ADV（Flags+Manuf 0xFFE0）
"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fastlink_emu as FL

BLE_CODE = 0x<BLE_CODE_HEX>          # home.bleCode (<BLE_CODE_B64>) -> 4-byte session key
MANUF_ID = 0xFFE0              # changeProtocolPara(0)

_ready = False


def init(platform=0, code=BLE_CODE):
    global _ready
    if _ready:
        return
    FL.call(FL.INIT, [0, 0])
    FL.call(FL.SET_PLAT, [platform])
    p = FL.HEAP + 0x1000
    FL.uc.mem_write(p, struct.pack('<I', code))
    FL.call(FL.SET_CODE, [p])
    _ready = True


def encode(head4, data16, flags=(0, 0, 0), typ=0, randv=None, platform=0, code=BLE_CODE):
    """head4: 4 bytes; data16: bytes (<=16); 回傳 40 bytes（body = out[15:39]）"""
    init(platform, code)
    if randv is not None:
        FL.RANDV[0] = randv & 0x7FFFFFFF
    d = bytes(data16)[:16].ljust(16, b'\x00')
    inb = bytearray(0x20)
    inb[0:4] = bytes(head4)[:4].ljust(4, b'\x00')
    inb[4:0x14] = d
    inb[0x14:0x16] = d[0x10:0x12]
    inb[0x19], inb[0x1a], inb[0x1b] = flags
    inb[0x1c:0x20] = struct.pack('<I', typ)
    pin = FL.HEAP + 0x2000
    FL.uc.mem_write(pin, bytes(inb))
    pout = FL.HEAP + 0x3000
    FL.uc.mem_write(pout, b'\x00' * 64)
    FL.call(FL.ENCODER, [pin, pout])
    return bytes(FL.uc.mem_read(pout, 40))


def body(head4, data16, **kw):
    """回傳 24-byte 加密載荷（= App 廣播的 manufacturer data）"""
    return encode(head4, data16, **kw)[15:39]


def ad_payload(head4, data16, **kw):
    """回傳完整 31-byte legacy ADV 資料：02 01 02 | 1b ff e0 ff | <24B>"""
    return bytes.fromhex('0201021bffe0ff') + body(head4, data16, **kw)


def _cli():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('head', help='4-byte head hex, e.g. d1010000')
    ap.add_argument('data', help='data hex (<=16B), e.g. 0000')
    ap.add_argument('--typ', type=lambda x: int(x, 0), default=0)
    ap.add_argument('--rand', type=lambda x: int(x, 0), default=None)
    a = ap.parse_args()
    out = encode(bytes.fromhex(a.head), bytes.fromhex(a.data), typ=a.typ, randv=a.rand)
    print('out :', out.hex())
    print('body:', out[15:39].hex())
    print('ad  :', ad_payload(bytes.fromhex(a.head), bytes.fromhex(a.data), typ=a.typ, randv=a.rand).hex())


if __name__ == '__main__':
    _cli()
