#!/usr/bin/env python3
"""TinySmart 燈控 CLI — 給日常用（關燈/開燈/指定房間）
用法:
  python3 lights.py off                      # 關全部燈
  python3 lights.py off 客廳                  # 關某房間
  python3 lights.py on 主臥                   # 開某房間
  python3 lights.py off 客廳 主臥             # 多房間
  python3 lights.py off 全屋                 # = 所有房間（roomId 0 是空殼，無效）
選項: --seqs N（每房 payload 數，預設1）--rounds N（預設4）--gap S（每格間隔秒，預設1.0）
      實測最少有效組合 = seqs1/rounds4/gap1.0（rounds×gap≈4 秒才收得到）
      （也可用環境變數 TINYSMART_SEQS / TINYSMART_ROUNDS / TINYSMART_GAP 覆寫）
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
    """{房間名: roomId} —— 只含「真的有燈」的房間。

    ⚠️ 2026-09-25 目視實測：API 的 rooms 有一個 roomId=0 的空殼（底下 0 顆燈），
    送 `roomId=0` **完全沒反應**（不是「全屋」）。全屋要自己展開成所有房間的集合。
    """
    m = {}
    for d in home['devices']:
        rn, rid = d.get('roomName'), d.get('roomId')
        if rn and rid is not None:
            m[rn] = rid
    return m


def _resolve(rm, want):
    """把房間名解析成 roomId 清單。'全屋' = 所有房間；want 空 = 全部。

    回傳 (rids, err)。重複的 roomId 會去重（避免同一房送兩次）。
    """
    all_ids = list(dict.fromkeys(rm.values()))
    if not want:
        return all_ids, None
    rids = []
    for w in want:
        if w in ('全屋', '全部', 'all'):
            rids.extend(all_ids)
        elif w in rm:
            rids.append(rm[w])
        else:
            return None, f"未知房間: {w}（可用: 全屋, {', '.join(rm)}）"
    return list(dict.fromkeys(rids)), None


DEFAULT_SEQS = 1      # 每房間 payload 數（不同 seq byte）
# ⚠️ 2026-09-25 實機測試（客廳 5 顆，目視驗證）：
#   seqs=1, rounds=4, gap=1.0        → ✅ 有效（客廳 on/off 都成功，1 房間約 7s）
#   seqs=6, rounds=4, gap=1.0        → ✅ 有效（約 34s，舊版等價參數）
#   seqs=1, rounds=2, gap=0.3        → ❌ 無效（3 房間 5s 全屋測試：燈沒反應）
# 結論：**時間要拉開（rounds × gap ≈ 4 秒）**才收得到，縮短間隔會失效。
# 預設故採「有效」組合 seqs=1 / rounds=4 / gap=1.0；要更快請自行測 rounds=3。
DEFAULT_ROUNDS = 4
DEFAULT_GAP = 1.0


def _send(codec, room_ids, on: bool, seqs: int = DEFAULT_SEQS,
          rounds: int = DEFAULT_ROUNDS, gap=DEFAULT_GAP):
    """一次廣播就把「所有房間」的 payload 一起送完。

    重點：**不要**在外層切片分批呼叫（那會讓第二個房間晚 25s 才收到、又慢）。
    同一輪內 payload 連續送出 → 各房間「同步」動作。
    """
    pays = []
    for rid in room_ids:
        d = cmd_group_switch(rid, on=on)
        for seq in range(1, seqs + 1):
            pays.append(codec.ad(head(seq), d))
    res = broadcast(pays, rounds=rounds, gap=gap)
    if getattr(res, 'returncode', 0) != 0:
        print(f"⚠️ 廣播失敗 rc={res.returncode}：{(res.stderr or '')[-300:]}")
    return len(pays)


def _pop_flags(rest):
    """從參數列取出 --seqs/--rounds/--gap，其餘視為房間名。"""
    seqs = int(os.environ.get('TINYSMART_SEQS', DEFAULT_SEQS))
    rounds = int(os.environ.get('TINYSMART_ROUNDS', DEFAULT_ROUNDS))
    gap = float(os.environ['TINYSMART_GAP']) if os.environ.get('TINYSMART_GAP') else DEFAULT_GAP
    want, i = [], 0
    while i < len(rest):
        a = rest[i]
        if a in ('--seqs', '--rounds', '--gap') and i + 1 < len(rest):
            v = rest[i + 1]
            if a == '--seqs':
                seqs = int(v)
            elif a == '--rounds':
                rounds = int(v)
            else:
                gap = float(v)
            i += 2
            continue
        want.append(a)
        i += 1
    return want, seqs, rounds, gap


def main(argv):
    if len(argv) < 2 or argv[1] in ('rooms', 'status', '-h', '--help'):
        home, _ = _load()
        rm = _room_map(home)
        print("可用房間：")
        total = 0
        for k, v in rm.items():
            n = sum(1 for d in home['devices'] if d.get('roomId') == v)
            total += n
            print(f"  {k}  (roomId={v}, {n} 顆)")
        print(f"  全屋  (roomId={list(dict.fromkeys(rm.values()))}, {total} 顆)")
        print("\n用法: python3 lights.py {on|off} [房間名...]   # 省略房間=全部")
        return 0

    act = argv[1].lower()
    if act not in ('on', 'off'):
        print(__doc__)
        return 2
    home, codec = _load()
    rm = _room_map(home)
    want, seqs, rounds, gap = _pop_flags(argv[2:])
    rids, err = _resolve(rm, want)
    if err:
        print(err)
        return 2
    n = _send(codec, rids, on=(act == 'on'), seqs=seqs, rounds=rounds, gap=gap)
    print(f"已送 {'開啟' if act == 'on' else '關閉'}：{want or '全部房間'} "
          f"(roomId={rids}) → {n} 個 payload（seqs={seqs}, rounds={rounds}, gap={gap}，一次同步廣播）")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
