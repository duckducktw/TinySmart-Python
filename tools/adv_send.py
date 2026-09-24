#!/usr/bin/env python3
"""用 raw HCI 直接把 31-byte 負載當 BLE 廣播送出（需 root）。
用法: sudo python3 adv_send.py <adv_type> <hex1> [hex2 ...]
  adv_type: 0=ADV_IND(可連) 3=ADV_NONCONN_IND(單向)
"""
import socket, struct, sys, time, subprocess

HCI_CHANNEL_USER = 1
sock = None


def open_user(dev=0):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s.bind((dev, HCI_CHANNEL_USER))
    s.settimeout(2.0)
    return s


def cmd(opcode, params=b"", wait=0.25):
    pkt = bytes([0x01]) + struct.pack("<H", opcode) + bytes([len(params)]) + params
    sock.send(pkt)
    time.sleep(wait)
    try:
        while True:
            sock.recv(1024)
    except Exception:
        pass


def adv(adv_type, payload, hold=0.45):
    # LE Set Advertising Parameters: int_min, int_max, type, own_addr_type,
    #                               peer_addr_type, peer_addr(6), chan_map, filter
    p = struct.pack("<HHBBB6sBB", 0x00A0, 0x00A0, adv_type, 0x00, 0x00,
                    b"\x00" * 6, 0x07, 0x00)
    cmd(0x2006, p)
    cmd(0x2008, bytes([len(payload)]) + payload)   # LE Set Advertising Data
    cmd(0x200A, b"\x01")                            # Enable
    time.sleep(hold)
    cmd(0x200A, b"\x00")                            # Disable
    time.sleep(0.05)


def main():
    global sock
    at = int(sys.argv[1])
    payloads = [bytes.fromhex(h) for h in sys.argv[2:]]
    subprocess.run(["hciconfig", "hci0", "down"], check=False)
    time.sleep(0.5)
    try:
        sock = open_user(0)
        for i, pl in enumerate(payloads, 1):
            assert 1 <= len(pl) <= 31, len(pl)
            print(f"[{i}/{len(payloads)}] adv_type={at} {pl.hex()}")
            adv(at, pl)
    finally:
        if sock:
            sock.close()
        subprocess.run(["hciconfig", "hci0", "up"], check=False)
        print("done")


if __name__ == "__main__":
    main()
