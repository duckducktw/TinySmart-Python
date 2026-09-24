#!/usr/bin/env python3
"""擴充廣播傳送器（對齊 App：ext adv + legacy PDU + 隨機廣播位址）。
用法: sudo python3 adv_ext.py <hex1> [hex2 ...]
"""
import socket, struct, sys, time, subprocess, random

HANDLE = 0x00
sock = None

def open_user(dev=0):
    HCI_CHANNEL_USER = 1
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s.bind((dev, HCI_CHANNEL_USER))
    return s

def cmd(op, params=b""):
    pkt = bytes([0x01]) + struct.pack("<H", op) + bytes([len(params)]) + params
    sock.send(pkt)
    time.sleep(0.02)

def rand_addr():
    b = bytearray(random.getrandbits(8) for _ in range(6))
    b[5] = (b[5] & 0x3F) | 0x00     # 非解析型私密位址（top2=00）
    return bytes(b)

def adv_ext(payload):
    ra = rand_addr()
    cmd(0x2035, bytes([HANDLE]) + ra)                      # Set Adv Set Random Address
    props = 0x0010                                          # legacy PDUs
    p = (bytes([HANDLE]) + struct.pack("<H", props)
         + struct.pack("<I", 0x0000A0)[:3] + struct.pack("<I", 0x0000A0)[:3]
         + bytes([0x07, 0x01, 0x00]) + b"\x00" * 6
         + bytes([0x00, 0xF1, 0x01, 0x01, 0x00, 0x00]))
    cmd(0x2036, p)                                          # Set Ext Adv Params
    cmd(0x2037, bytes([HANDLE, 0x03, 0x00, len(payload)]) + payload)   # Set Ext Adv Data
    cmd(0x2039, bytes([0x01, 0x01, HANDLE]) + struct.pack("<H", 0) + bytes([0x00]))  # Enable
    time.sleep(0.45)
    cmd(0x2039, bytes([0x00, 0x00]))                        # Disable all

def main():
    global sock
    payloads = [bytes.fromhex(h) for h in sys.argv[1:]]
    subprocess.run(["hciconfig", "hci0", "down"], check=False)
    time.sleep(0.4)
    try:
        sock = open_user(0)
        for i, pl in enumerate(payloads, 1):
            assert 1 <= len(pl) <= 31, len(pl)
            print(f"[{i}/{len(payloads)}] ext {pl.hex()}", flush=True)
            adv_ext(pl)
    finally:
        try: sock.close()
        except Exception: pass
        subprocess.run(["hciconfig", "hci0", "up"], check=False)
        print("done")

if __name__ == "__main__":
    main()
