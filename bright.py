#!/usr/bin/env python3
"""TinySmart 亮度/色溫設定（走 CCT 指令 0x93）。

用法:
  python3 bright.py 主臥 255            # 亮度最大，中間色溫
  python3 bright.py 主臥 128 255 0      # 亮度128 最暖(w=255,y=0)
  python3 bright.py 主臥 255 0 255      # 亮度最大 最冷
  python3 bright.py 主臥 255 --dry
w = 暖光通道(255=最暖), y = 冷光通道(255=最冷)
"""
from __future__ import annotations
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))

from tinysmart_full import (QrCodec, fetch_home, fetch_mesh_key, Codec,
                            head, cmd_group_cct, broadcast)

QR_FILE = os.path.join(HERE, 'tools', 'newqr.txt')


def _load():
    qr = open(QR_FILE).read().strip()
    info = QrCodec.decrypt(qr)
    home = fetch_home(info['shareID'])
    codec = Codec(home['key4'].to_bytes(4, 'big'), fetch_mesh_key())
    return home, codec


def _room_map(home):
    m = {'全屋': 0}
    for d in home['devices']:
        rn, rid = d.get('roomName'), d.get('roomId')
        if rn and rid is not None:
            m[rn] = rid
    return m


def main(argv):
    args = [a for a in argv[1:] if not a.startswith('--')]
    dry = '--dry' in argv
    if len(args) < 2:
        print(__doc__)
        return 2
    room = args[0]
    bright = int(args[1])
    w = int(args[2]) if len(args) > 2 else 128
    y = int(args[3]) if len(args) > 3 else 128

    home, codec = _load()
    rm = _room_map(home)
    if room not in rm:
        print(f"未知房間: {room}（可用: {', '.join(rm)}）")
        return 2
    rid = rm[room]

    data = cmd_group_cct(rid, bright, w, y)
    pays = [codec.ad(head(seq, addr=0), data) for seq in range(1, 7)]
    print(f"房間={room}(roomId={rid}) 亮度={bright} w={w} y={y} data={data.hex()}")
    if dry:
        print("(dry-run)")
        return 0
    for i in range(0, len(pays), 6):
        broadcast(pays[i:i + 6], rounds=2)
    print(f"已廣播 {len(pays)} 個 payload")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
