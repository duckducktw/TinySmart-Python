"""btsnoop 解析：帶時間戳印出 adv 指令（決定性實驗用）。
用法: python3 ts_dump.py <btsnoop> [--since <unix_s>]
"""
import struct, sys, datetime, collections

OFFSET = 0x00dcddb30f2f8000  # btsnoop epoch -> unix (usec)

def us_to_unix(us):
    return us - OFFSET

path = sys.argv[1]
since = None
if '--since' in sys.argv:
    since = int(sys.argv[sys.argv.index('--since') + 1])

ADV = {0x2006: "SetAdvParams", 0x2008: "SetAdvData", 0x2009: "SetScanRespData",
       0x200A: "SetAdvEnable", 0x2035: "SetAdvSetRandAddr", 0x2036: "SetExtAdvParams",
       0x2037: "SetExtAdvData", 0x2038: "SetExtScanRespData", 0x2039: "SetExtAdvEnable",
       0x203A: "RemoveAdvSet", 0x203B: "ClearAdvSets"}

d = open(path, 'rb').read()
off = 16
rows = []
while off + 24 <= len(d):
    o, incl, fl, dr = struct.unpack('>IIII', d[off:off+16])
    ts = struct.unpack('>Q', d[off+16:off+24])[0]
    rec = d[off+24:off+24+incl]
    off += 24 + incl
    if not rec or rec[0] != 0x01 or len(rec) < 4:
        continue
    op = struct.unpack('<H', rec[1:3])[0]
    plen = rec[3]
    params = rec[4:4+plen]
    if op in ADV:
        t = us_to_unix(ts) / 1e6
        s = datetime.datetime.utcfromtimestamp(t).strftime('%H:%M:%S.%f')[:-3]
        rows.append((t, s, ADV[op], params.hex()))

print(f"total adv-cmd records={len(rows)}")
if since:
    rows = [r for r in rows if r[0] >= since]
    print(f"after filter(since={since}) => {len(rows)}")

cnt = collections.Counter(r[2] for r in rows)
print("counts:", dict(cnt))

for t, s, name, h in rows:
    print(f"{s}  {name:12} {h}")
