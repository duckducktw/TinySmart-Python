#!/usr/bin/env python3
"""TinySmart 亮度/色溫設定（CCT 指令 0x93）。

用法:
  python3 bright.py 主臥 255            # 亮度最大，中間色溫
  python3 bright.py 全屋 200            # 全屋
  python3 bright.py 主臥 128 255 0      # 亮度128 最暖(w=255,y=0)
  python3 bright.py 主臥 255 0 255      # 亮度最大 最冷
  python3 bright.py 主臥 255 --dry
選項: --seqs N --rounds N --gap S（同 lights.py；預設 1/4/1.0）
w = 暖光通道(255=最暖), y = 冷光通道(255=最冷)
"""
from __future__ import annotations
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))

from tinysmart_full import cmd_group_cct, broadcast, head
from lights import _load, _room_map, _resolve, _pop_flags, DEFAULT_SEQS, DEFAULT_ROUNDS, DEFAULT_GAP


def main(argv):
    dry = '--dry' in argv
    rest = [a for a in argv[1:] if a != '--dry']
    want, seqs, rounds, gap = _pop_flags(rest)
    if len(want) < 2:
        print(__doc__)
        return 2
    room, bright = want[0], int(want[1])
    w = int(want[2]) if len(want) > 2 else 128
    y = int(want[3]) if len(want) > 3 else 128

    home, codec = _load()
    rm = _room_map(home)
    rids, err = _resolve(rm, [room])
    if err:
        print(err)
        return 2
    pays = []
    for rid in rids:
        data = cmd_group_cct(rid, bright, w, y)
        for seq in range(1, seqs + 1):
            pays.append(codec.ad(head(seq), data))
    print(f"房間={room} roomId={rids} 亮度={bright} w={w} y={y} "
          f"payload={len(pays)} seqs={seqs} rounds={rounds} gap={gap}")
    if dry:
        print("(dry-run)")
        return 0
    res = broadcast(pays, rounds=rounds, gap=gap)
    if getattr(res, 'returncode', 0) != 0:
        print(f"⚠️ 廣播失敗 rc={res.returncode}：{(res.stderr or '')[-300:]}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
