#!/usr/bin/env python3
"""TinySmart 燈控 CLI — 給日常用（關燈/開燈/指定房間）
用法:
  python3 lights.py off                      # 關全部燈
  python3 lights.py off 客廳                  # 關某房間
  python3 lights.py on 主臥                   # 開某房間
  python3 lights.py off 客廳 主臥             # 多房間
  python3 lights.py rooms                    # 列出房間與燈具
  python3 lights.py status                   # 同上（別名）
環境: 需要 sudo 反向廣播（HCI raw socket）；QR 放 tools/newqr.txt
"""
from __future__ import annotations
import os, sys, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))

from tinysmart_full import (QrCodec, fetch_home, fetch_mesh_key, Codec,
                            head, cmd_group_switch, broadcast)

QR_FILE = os.path.join(HERE, 'tools', 'newqr.txt')


def _load():
    qr = open(QR_FILE).read().strip()
    info = QrCodec.decrypt(qr)
    home = fetch_home(info['shareID'])
    codec = Codec(home['key4'].to_bytes(4, 'big'), fetch_mesh_key())
    return home, codec


def _room_map(home):
    """{房間名: roomId}，另加 '全屋':0"""
    m = {'全屋': 0}
    for d in home['devices']:
        rn, rid = d.get('roomName'), d.get('roomId')
        if rn and rid is not None:
            m[rn] = rid
    return m


def _send(codec, room_ids, on: bool):
    pays = []
    for rid in room_ids:
        d = cmd_group_switch(rid, on=on)
        for seq in range(1, 7):
            pays.append(codec.ad(head(seq, addr=0), d))
    total = len(pays)
    for i in range(0, total, 6):
        broadcast(pays[i:i + 6], rounds=2)
    return total


def main(argv):
    if len(argv) < 2 or argv[1] in ('rooms', 'status', '-h', '--help'):
        home, _ = _load()
        print("可用房間：")
        for k, v in _room_map(home).items():
            n = sum(1 for d in home['devices'] if d.get('roomId') == v)
            print(f"  {k}  (roomId={v}, {n} 顆)")
        print("\n用法: python3 lights.py {on|off} [房間名...]   # 省略房間=全部")
        return 0

    act = argv[1].lower()
    if act not in ('on', 'off'):
        print(__doc__)
        return 2
    home, codec = _load()
    rm = _room_map(home)
    want = argv[2:]
    if not want:
        rids = [rm[k] for k in rm]
    else:
        rids = []
        for w in want:
            if w not in rm:
                print(f"未知房間: {w}（可用: {', '.join(rm)}）")
                return 2
            rids.append(rm[w])
    n = _send(codec, rids, on=(act == 'on'))
    print(f"已送 {'開啟' if act == 'on' else '關閉'}：{want or '全部房間'} "
          f"(roomId={rids}) → {n} 個 payload")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
