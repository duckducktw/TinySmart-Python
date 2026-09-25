#!/usr/bin/env python3
"""TinySmart 擴充廣播重播器 v2 — 忠實複製 App 實機 HCI 序列。
App 行為：對 handle {3,6,7,8,9} 各做 SetExtAdvParams→SetRandAddr→SetExtAdvData→Enable，
每 ~1s 一輪（先 disable 5 個 set 再重設），共 4 輪。
用法: sudo python3 replay_adv2.py <hexAD1> [hexAD2 ...]
每個 AD = 31-byte legacy PDU（含 Flags + ManufacturerData 0xFFE0）。
"""
import socket, struct, sys, time, subprocess, random

HANDLES = [0x03, 0x06, 0x07, 0x08, 0x09]
ROUNDS = 4          # 預設 4 輪（與 App 實機一致）；可用 --rounds N 覆寫
GAP = 1.0

def open_user(dev=0):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s.bind((dev, 1))          # HCI_CHANNEL_USER
    s.settimeout(1.0)
    return s

def cmd(sock, op, params=b""):
    sock.send(bytes([0x01]) + struct.pack("<H", op) + bytes([len(params)]) + params)
    time.sleep(0.015)

def rand_addr():
    b = bytearray(random.getrandbits(8) for _ in range(6))
    b[5] &= 0x3F               # 非解析型私密位址
    return bytes(b)

def params_for(h):
    return (bytes([h]) + struct.pack("<H", 0x0013)
            + struct.pack("<I", 160)[:3] + struct.pack("<I", 210)[:3]
            + bytes([0x07, 0x01, 0x00]) + b"\x00" * 6
            + bytes([0x00, 0x01, 0x01, 0x00, 0x01, h, 0x00]))

def disable_all(sock):
    cmd(sock, 0x2039, bytes([0x00, 0x00]))

def arm(sock, h, payload):
    cmd(sock, 0x2036, params_for(h))
    cmd(sock, 0x2035, bytes([h]) + rand_addr())
    cmd(sock, 0x2037, bytes([h, 0x03, 0x00, len(payload)]) + payload)
    cmd(sock, 0x2039, bytes([0x01, 0x01, h]) + struct.pack("<H", 0) + bytes([0x00]))

def main():
    global ROUNDS, GAP
    argv = sys.argv[1:]
    rounds, gap = ROUNDS, GAP
    payloads = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--rounds" and i + 1 < len(argv):
            rounds = int(argv[i + 1]); i += 2; continue
        if a == "--gap" and i + 1 < len(argv):
            gap = float(argv[i + 1]); i += 2; continue
        payloads.append(bytes.fromhex(a)); i += 1
    ROUNDS, GAP = rounds, gap
    if not payloads:
        print("need payloads"); return
    print(f"rounds={ROUNDS} gap={GAP} payloads={len(payloads)}", flush=True)
    subprocess.run(["hciconfig", "hci0", "down"], check=False); time.sleep(0.5)
    sock = None
    try:
        sock = open_user(0)
        disable_all(sock); time.sleep(0.1)
        for r in range(ROUNDS):
            for i, pl in enumerate(payloads):
                assert 1 <= len(pl) <= 31
                for h in HANDLES:
                    arm(sock, h, pl)
                print(f"  round={r+1} i={i+1} handles={HANDLES} {pl.hex()}", flush=True)
                time.sleep(GAP)
            disable_all(sock)
        print("done")
    finally:
        try:
            if sock: sock.close()
        except Exception: pass
        subprocess.run(["hciconfig", "hci0", "up"], check=False)

if __name__ == "__main__":
    main()
