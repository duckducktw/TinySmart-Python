import struct, sys, collections

path = sys.argv[1]
d = open(path, 'rb').read()
ADV_CMDS = {0x2006: "LE_SetAdvParams", 0x2008: "LE_SetAdvData", 0x2009: "LE_SetScanRespData",
            0x200A: "LE_SetAdvEnable", 0x2036: "LE_SetExtAdvParams", 0x2037: "LE_SetExtAdvData",
            0x2038: "LE_SetExtScanRespData", 0x2039: "LE_SetExtAdvEnable", 0x2035: "LE_SetAdvSetRandAddr"}
off = 16
cnt = collections.Counter()
dumps = collections.defaultdict(set)
tail = []
while off + 24 <= len(d):
    o, incl, fl, dr = struct.unpack('>IIII', d[off:off+16])
    rec = d[off+24:off+24+incl]
    off += 24 + incl
    if not rec or rec[0] != 0x01 or len(rec) < 4:
        continue
    op = struct.unpack('<H', rec[1:3])[0]
    plen = rec[3]; params = rec[4:4+plen]
    if op in ADV_CMDS:
        cnt[ADV_CMDS[op]] += 1
        dumps[ADV_CMDS[op]].add(params.hex())
        tail.append((ADV_CMDS[op], params.hex()))
print("adv commands:", dict(cnt))
for k, v in dumps.items():
    print(f"\n== {k}  ({len(v)} unique) ==")
    for h in list(v)[:12]:
        print("  ", h)
print("\n== 時間序（最後 25 筆）==")
for k, h in tail[-25:]:
    print(f"  {k:22} {h}")
