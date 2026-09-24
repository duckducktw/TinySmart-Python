#!/usr/bin/env python3
"""btsnoop_hci.log 解析器 — 取出 App 在藍牙上實際送出的協議。

用法:
  python3 blesnoop.py <btsnoop_hci.log> [--mac FC:42:65:6C:XX:XX] [--writes-only]

取得 log（免 root）:
  adb shell settings put secure bluetooth_hci_log 1
  adb shell cmd bluetooth_manager disable && adb shell cmd bluetooth_manager enable
  adb bugreport /tmp/br        # → 解開 zip 內 FS/data/log/bt/btsnoop_hci.log

※ HCI 層看到的是「明文」ATT payload（LE 鏈路層加密在控制器之下），
  所以 GATT write 的內容 = App 真正送出的位元組。
"""
import struct, sys, collections

OPS = {0x01:"ErrorRsp",0x02:"MtuReq",0x03:"MtuRsp",0x04:"FindInfoReq",0x05:"FindInfoRsp",
       0x08:"ReadByTypeReq",0x09:"ReadByTypeRsp",0x0A:"ReadReq",0x0B:"ReadRsp",
       0x10:"ReadByGroupReq",0x11:"ReadByGroupRsp",0x12:"WriteReq",0x13:"WriteRsp",
       0x52:"WriteCmd",0x1B:"Notify",0x1D:"Indicate"}
LE_META = {0x01:"ConnComplete",0x02:"AdvReport",0x03:"ConnUpdate",0x05:"LTKReq",
           0x0A:"EnhancedConnComplete",0x0D:"ExtAdvReport",0x12:"ChanSelAlgo"}


def parse(path, want_mac=None, writes_only=False):
    d = open(path, "rb").read()
    if d[:8] != b"btsnoop\x00":
        sys.exit("not btsnoop")
    off, n = 16, 0
    handle2addr, writes, stats = {}, [], collections.Counter()
    while off + 24 <= len(d):
        orig, incl, flags, drops = struct.unpack(">IIII", d[off:off+24-8])
        off += 24 + incl
        rec = d[off-incl:off]
        n += 1
        if not rec:
            continue
        direction = "TX" if (flags & 1) else "RX"      # 1 = 手機→控制器(送出)
        t = rec[0]
        if t == 0x02 and len(rec) >= 5:                # ACL
            h = struct.unpack("<H", rec[1:3])[0] & 0x0FFF
            payload = rec[5:5+struct.unpack("<H", rec[3:5])[0]]
            if len(payload) >= 5 and struct.unpack("<H", payload[2:4])[0] == 0x0004:
                op = payload[4]
                stats[OPS.get(op, hex(op))] += 1
                if len(payload) >= 7:
                    vh = struct.unpack("<H", payload[5:7])[0]
                    val = payload[7:]
                    if op in (0x12, 0x52, 0x1B, 0x1D):
                        writes.append((h, direction, OPS[op], vh, val.hex()))
        elif t == 0x04 and len(rec) >= 5 and rec[1] == 0x3E:   # LE meta
            sub = rec[3]
            stats["LE/" + LE_META.get(sub, hex(sub))] += 1
            if sub == 0x0A and len(rec) >= 15:                 # Enhanced Conn Complete
                addr = rec[9:15][::-1].hex(":").upper()
                h = struct.unpack("<H", rec[5:7])[0] & 0x0FFF
                handle2addr[h] = addr
            elif sub == 0x01 and len(rec) >= 15:               # Conn Complete (legacy)
                addr = rec[9:15][::-1].hex(":").upper()
                h = struct.unpack("<H", rec[5:7])[0] & 0x0FFF
                handle2addr.setdefault(h, addr)
    print(f"records={n}")
    print("ATT/LE 統計:", dict(stats))
    print(f"\n連線(handle→位址):")
    for h, a in sorted(handle2addr.items()):
        print(f"  handle {h:>5}  {a}")
    print(f"\nATT writes/notify 共 {len(writes)} 筆")
    seen = 0
    for h, dirn, op, vh, val in writes:
        addr = handle2addr.get(h, "?")
        if want_mac and want_mac.replace(":", "").upper() not in addr.replace(":", "").upper():
            continue
        seen += 1
        if seen <= 60:
            print(f"  {dirn} handle={h} {addr} {op} 特徵=0x{vh:04X} len={len(val)//2} {val}")
    if want_mac:
        print(f"  (符合 {want_mac} 的筆數: {seen})")
    return handle2addr, writes


if __name__ == "__main__":
    a = sys.argv[1:]
    mac = None
    if "--mac" in a:
        i = a.index("--mac"); mac = a[i+1]
    parse(a[0], mac, "--writes-only" in a)
