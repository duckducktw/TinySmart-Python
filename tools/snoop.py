import struct, sys, collections

path = sys.argv[1]
data = open(path, 'rb').read()

# btsnoop: 8-byte magic + 4 version + 4 datalink, then records
assert data[:8] == b'btsnoop\x00', data[:8]
datalink = struct.unpack('>I', data[12:16])[0]
print(f"datalink={datalink} (1001=HCI UART) size={len(data)}")

off = 16
acls = collections.Counter()
att = collections.Counter()
att_writes = []
le_adv = collections.Counter()
conn_addrs = []
n = 0
while off + 24 <= len(data):
    orig, incl, flags, drops = struct.unpack('>IIII', data[off:off+16])
    off += 24 + incl
    if incl == 0:
        continue
    rec = data[off-incl:off]
    n += 1
    if not rec:
        continue
    ptype = rec[0]
    if ptype == 0x02 and len(rec) >= 5:          # ACL
        h = struct.unpack('<H', rec[1:3])[0]
        handle = h & 0x0FFF
        dlen = struct.unpack('<H', rec[3:5])[0]
        payload = rec[5:5+dlen]
        acls[handle] += 1
        if len(payload) >= 4:
            l2len = struct.unpack('<H', payload[0:2])[0]
            cid = struct.unpack('<H', payload[2:4])[0]
            if cid == 0x0004 and len(payload) >= 5:   # ATT
                op = payload[4]
                att[hex(op)] += 1
                if op in (0x12, 0x52, 0x1b) and len(payload) >= 7:
                    hh = struct.unpack('<H', payload[5:7])[0]
                    val = payload[7:7+l2len]
                    att_writes.append((handle, op, hh, val[:40].hex()))
    elif ptype == 0x04 and len(rec) >= 3:        # EVENT
        ev = rec[1]
        if ev == 0x3E and len(rec) >= 5:         # LE Meta
            sub = rec[3]
            if sub == 0x02:                      # Advertising Report
                le_adv['adv_report'] += 1
                # addr type/addr at offset 7..
                try:
                    addr = rec[9:15][::-1].hex(':')
                    conn_addrs.append(addr)
                except Exception:
                    pass
            else:
                le_adv[f'le_meta_{hex(sub)}'] += 1
print(f"records={n}")
print("ACL per handle:", dict(acls))
print("ATT opcodes:", dict(att))
print("LE meta:", dict(le_adv))
print(f"\nATT writes/notify: {len(att_writes)}")
for w in att_writes[:40]:
    print("  handle=%d op=0x%02x valhandle=0x%04x val=%s" % w[:4])
adv = collections.Counter(conn_addrs)
print(f"\nadvertising addrs seen: {len(adv)}")
for a, c in adv.most_common(12):
    print(f"  {a}  x{c}")
