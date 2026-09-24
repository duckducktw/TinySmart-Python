#!/usr/bin/env python3
"""TinySmart 擴充廣播重播器 — 完全複製 App 實機 HCI 序列（handle 3）。
用法: sudo python3 replay_adv.py <hexAD1> [hexAD2 ...]
每個 AD 為 31-byte legacy PDU（含 Flags + ManufacturerData 0xFFE0）。
送法：每個 payload 一個 burst，間隔 ~1s，共重複 --repeat 次。
"""
import socket, struct, sys, time, subprocess, random, os

HANDLE = 0x03
REPEAT = 4
BURST_GAP = 1.0

def open_user(dev=0):
    HCI_CHANNEL_USER = 1
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s.bind((dev, HCI_CHANNEL_USER))
    s.settimeout(1.0)
    return s

def cmd(sock, op, params=b""):
    pkt = bytes([0x01]) + struct.pack("<H", op) + bytes([len(params)]) + params
    sock.send(pkt)
    time.sleep(0.02)

def rand_addr():
    b = bytearray(random.getrandbits(8) for _ in range(6))
    b[5] = (b[5] & 0x3F) | 0x00          # 非解析型私密位址
    return bytes(b)

def set_params(sock):
    ra = rand_addr()
    cmd(sock, 0x2035, bytes([HANDLE]) + ra)               # Set Adv Set Random Address
    # 完全複製實機: props=0x0013 legacy+connectable+scannable, 160..210, chmap 07,
    # own_addr=1(random), peer=0, filter=0, txpower=1, phy 1/1, sid=3
    p = (bytes([HANDLE]) + struct.pack("<H", 0x0013)
         + struct.pack("<I", 160)[:3] + struct.pack("<I", 210)[:3]
         + bytes([0x07, 0x01, 0x00]) + b"\x00" * 6
         + bytes([0x00, 0x01, 0x01, 0x00, 0x01, HANDLE, 0x00]))
    cmd(sock, 0x2036, p)                                  # Set Ext Adv Params
    return ra

def send_data(sock, payload):
    cmd(sock, 0x2037, bytes([HANDLE, 0x03, 0x00, len(payload)]) + payload)

def enable(sock, on):
    if on:
        cmd(sock, 0x2039, bytes([0x01, 0x01, HANDLE]) + struct.pack("<H", 0) + bytes([0x00]))
    else:
        cmd(sock, 0x2039, bytes([0x00, 0x00]))

def main():
    payloads = [bytes.fromhex(h) for h in sys.argv[1:]]
    if not payloads:
        print("need payloads"); return
    subprocess.run(["hciconfig", "hci0", "down"], check=False)
    time.sleep(0.5)
    sock = None
    try:
        sock = open_user(0)
        set_params(sock)
        enable(sock, False); time.sleep(0.1)
        for rep in range(REPEAT):
            for i, pl in enumerate(payloads):
                assert 1 <= len(pl) <= 31, len(pl)
                send_data(sock, pl)
                enable(sock, True)
                print(f"  burst rep={rep+1} i={i+1} len={len(pl)} {pl.hex()}", flush=True)
                time.sleep(BURST_GAP)
        enable(sock, False)
    finally:
        try:
            if sock: sock.close()
        except Exception: pass
        subprocess.run(["hciconfig", "hci0", "up"], check=False)
        print("done")

if __name__ == "__main__":
    main()
