#!/usr/bin/env python3
"""TinySmart 完整控制模組（Python 重實作）— 2026-09-24

完整鏈路：
  QR (FTDSF|2|b64) ─► shareID ─► 分享API ─► 家庭模型(房間/燈具/bleCode)
  QueryFlashMeshCode API ─► meshKey(16B, AES key)
  ble_fast_link_init(0, 86, bleCode4, meshKey) + set_protocol_platform(2)
  encode(head, data) ─► body24 ─► AD(02 01 02 1b ff e0 ff + body) ─► HCI 擴充廣播

head = [ (addr>>8 & 0x0F)+OFFSET , seq , ctrl , 0 ]
data（12B）:
  groupControl 開關 : 43 <pt1> <pt0> <groupId> <isOpen?brightness:0> 00*7
  groupControl CCT  : 93 <pt1> <pt0> <groupId> <brightness> 00 00 00 <wLight> <yLight> 00 00
  setSwitchControllerOnOffGroup : 53 <pt1> <pt0> <groupId> <ctrl> <para> 00*6
"""
from __future__ import annotations
import base64, json, os, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))

QR_KEY = bytes.fromhex("1a2c3b161819a6e7954623a7d6e8e116")
QR_IV = b"ftd95279527a2c3c"
SHARE_API = "https://flashsmart.icoding.net.cn/flashsmart/queryShareInfo"
MESHKEY_API = "https://ftdauth.jasonghost.com:9527/wechatAuth/ftdAuth/QueryFlashMeshCode"

BLE_SOA = "tools/fl_encode.so"      # 佔位：改用 emulator
SO = '/tmp/tsx/lib/arm64-v8a/libflashsmartencode.so'


# ───────────────────────────── QR ─────────────────────────────
class QrCodec:
    @staticmethod
    def decrypt(qr_string: str) -> dict:
        from Crypto.Cipher import AES
        parts = qr_string.strip().split("|")
        if len(parts) < 3 or parts[0] != "FTDSF":
            raise ValueError("不是 FTDSF QR")
        raw = base64.b64decode(parts[2])
        pt = AES.new(QR_KEY, AES.MODE_CBC, QR_IV).decrypt(raw)
        pt = pt[: -pt[-1]] if pt and 1 <= pt[-1] <= 16 else pt
        return json.loads(pt.decode("utf-8", "ignore").strip("\x00"))


# ───────────────────────────── 雲端 ─────────────────────────────
def _post_json(url: str, obj: dict) -> dict:
    body = base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()
    hdr = ["-H", "Content-Type: application/json;charset=utf-8"]
    out = subprocess.run(["curl", "-s", "-m", "25", "-X", "POST", url, "-d", body, *hdr],
                         capture_output=True, text=True).stdout
    return json.loads(out)


def fetch_home(share_id: str, member_id: str = "1") -> dict:
    """分享API → {home, rooms, devices, key4, groups}"""
    j = _post_json(SHARE_API, {"shareId": share_id, "memberId": str(member_id)})
    data = j.get("data")
    if isinstance(data, str):
        data = json.loads(base64.b64decode(data).decode())
    sd = json.loads(base64.b64decode(data["memberInfo"]["shareDeviceJson"]).decode())
    home = sd.get("home", {})
    key4 = int.from_bytes(base64.b64decode(home["bleCode"])[:4], "big") if home.get("bleCode") else None
    devs = []
    for d in sd.get("devices", []):
        d = dict(d)
        if d.get("mac"):
            d["mac_clean"] = d["mac"].rstrip(":")
        devs.append(d)
    return {"home": home, "rooms": sd.get("rooms", []), "devices": devs,
            "groups": sd.get("groups", []), "scenes": sd.get("scenes", []), "key4": key4}


_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'meshkey.txt')

def fetch_mesh_key(use_cache_fallback: bool = True) -> bytes:
    """QueryFlashMeshCode → 16-byte AES key（此端點吃「原始 JSON」body，非 base64）。
    成功時寫入 meshkey.txt 快取；失敗時回退用快取。"""
    try:
        out = subprocess.run(["curl", "-s", "-m", "25", "-X", "POST", MESHKEY_API,
                              "-H", "Content-Type: application/json;charset=utf-8",
                              "-d", "{}"], capture_output=True, text=True).stdout
        key = json.loads(out)["data"].strip()
        if len(key) >= 32:
            try:
                open(_CACHE, "w").write(key)
            except Exception:
                pass
            return bytes.fromhex(key)
    except Exception:
        pass
    if use_cache_fallback and os.path.exists(_CACHE):
        return bytes.fromhex(open(_CACHE).read().strip())
    raise RuntimeError("QueryFlashMeshCode 失敗且無快取")


# ───────────────────────────── 編解碼 ─────────────────────────────
class Codec:
    """Tool2 (libflashsmartencode.so) 編解碼 — Unicorn 模擬。"""
    def __init__(self, ble_code4: bytes, mesh_key: bytes):
        import fastlink_emu as FL
        from fastlink_emu import uc, HEAP
        self.FL, self.uc, self.HEAP = FL, uc, HEAP
        FL.call(FL.INIT, [0, 0])
        pc = HEAP + 0x1000
        uc.mem_write(pc, ble_code4.ljust(4, b"\x00")[:4])
        pk = HEAP + 0x1200
        uc.mem_write(pk, mesh_key)
        FL.call(0x2700, [0, 86, pc, pk])       # ble_fast_link_init(0, customId=86, bleCode4, key)
        FL.call(0x288c, [2])                   # set_protocol_platform(2)

    def encode(self, head: bytes, data: bytes, rand: int | None = None) -> bytes:
        FL, uc, HEAP = self.FL, self.uc, self.HEAP
        FL.RANDV[0] = struct.unpack("<I", os.urandom(4))[0] & 0x7FFFFFFF if rand is None else rand
        inb = bytearray(0x20)
        inb[0:4] = head.ljust(4, b"\x00")[:4]
        inb[4:20] = data.ljust(16, b"\x00")[:16]
        pin = HEAP + 0x2000
        uc.mem_write(pin, bytes(inb))
        po = HEAP + 0x3000
        uc.mem_write(po, b"\x00" * 64)
        FL.call(FL.ENCODER, [pin, po])
        return bytes(uc.mem_read(po, 40))[15:39]

    def decode(self, body24: bytes):
        FL, uc, HEAP = self.FL, self.uc, self.HEAP
        buf = HEAP + 0x4000
        uc.mem_write(buf, b"\x1b\xff\xe0\xff" + body24)
        out = HEAP + 0x6000
        uc.mem_write(out, b"\x00" * 64)
        r = FL.call(0x3e80, [buf, 28, out]) & 0xFFFFFFFF
        return (r, bytes(uc.mem_read(out, 16))) if r == 0 else (r, None)

    def ad(self, head: bytes, data: bytes, rand: int | None = None) -> bytes:
        return bytes.fromhex("0201021bffe0ff") + self.encode(head, data, rand)


# ───────────────────────────── 指令 ─────────────────────────────
# head 格式（實機對拍解出，非猜測）：
#   head = [ (addr>>8 & 0x0F) + HEAD_BASE , seq , HEAD_CTRL , 0 ]
#   - HEAD_BASE=208 由實機 frame (`d0 <seq> 03 <chk>`) 反推；addr 1–9 → 0xD0
#   - HEAD_CTRL=3 由實機 frame 反推（來源為 App 內部狀態，非 QR 資料）
#   - head[3] 由 encode 產生檢查碼，輸入填 0
HEAD_BASE = 208
HEAD_CTRL = 3
# productType：App 內建的產品線常數（Dart 端無此字串、亦非裝置欄位推導）。
# 「雙色燈」(type=2ba8) 實機值為 (pt1, pt0) = (0x2A, 0xA8)。
PRODUCT_TYPE_DEFAULT = (0x2A, 0xA8)

def head(seq: int, addr: int = 0, ctrl: int = HEAD_CTRL) -> bytes:
    base = ((addr >> 8) & 0x0F) + HEAD_BASE
    return bytes([base & 0xFF, seq & 0xFF, ctrl & 0xFF, 0x00])


def cmd_group_switch(group_id: int, on: bool, brightness: int = 0xFF,
                     pt=PRODUCT_TYPE_DEFAULT) -> bytes:
    """groupControl 開/關（groupId = 房間 roomId）。"""
    d = bytearray(12)
    d[0] = 0x43
    d[1], d[2] = pt[0], pt[1]
    d[3] = group_id & 0xFF
    d[4] = (brightness & 0xFF) if on else 0
    return bytes(d)


def cmd_group_cct(group_id: int, brightness: int, w: int, y: int,
                  pt=PRODUCT_TYPE_DEFAULT) -> bytes:
    d = bytearray(12)
    d[0] = 0x93
    d[1], d[2] = pt[0], pt[1]
    d[3] = group_id & 0xFF
    d[4] = brightness & 0xFF
    d[8] = w & 0xFF
    d[9] = y & 0xFF
    return bytes(d)


def cmd_switch_group(group_id: int, ctrl: int, para: int = 0,
                     pt=PRODUCT_TYPE_DEFAULT) -> bytes:
    d = bytearray(12)
    d[0] = 0x53
    d[1], d[2] = pt[0], pt[1]
    d[3] = group_id & 0xFF
    d[4] = ctrl & 0xFF
    d[5] = para & 0xFF
    return bytes(d)


# ───────────────────────────── 廣播 ─────────────────────────────
def _ensure_askpass() -> str:
    """確保 sudo askpass 腳本存在（內容印出 ~/sudo.pwd）。回傳路徑。"""
    p = "/tmp/askpass.sh"
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write("#!/bin/sh\ncat ~/sudo.pwd\n")
        os.chmod(p, 0o755)
    return p


def broadcast(payloads: list[bytes], rounds: int = 4, handles=(3, 6, 7, 8, 9),
              gap: float | None = None):
    """以 sudo 執行 tools/replay_adv2.py（HCI_CHANNEL_USER 擴充廣播）。
    一次呼叫即把所有 payload 送完：同一輪內所有 payload 連續送出，
    因此多房間會「同步」收到指令（不要在外層切片分批跑，那樣會變慢又不同步）。
    注意：本函式自己處理 sudo，呼叫端請用「一般使用者」執行，不要再加 sudo。"""
    ask = _ensure_askpass()
    ad = os.path.join(HERE, "tools", "replay_adv2.py")
    args = " ".join(p.hex() for p in payloads)
    opts = f"--rounds {int(rounds)}" + (f" --gap {gap}" if gap is not None else "")
    cmd = f"SUDO_ASKPASS={ask} sudo -A -p '' python3 {ad} {opts} {args}"
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)


def make_off_payloads(codec: Codec, group_id: int, pt=(0x2A, 0xA8), n: int = 8):
    data = cmd_group_switch(group_id, on=False, pt=pt)
    return [codec.ad(head(seq), data) for seq in range(1, n + 1)]


if __name__ == "__main__":
    qr = open(os.path.join(HERE, "tools", "newqr.txt")).read().strip()
    info = QrCodec.decrypt(qr)
    print("QR:", info)
    home = fetch_home(info["shareID"])
    print("key4:", hex(home["key4"]) if home["key4"] else None)
    rooms = {}
    for d in home["devices"]:
        rooms.setdefault(d.get("roomName"), []).append((d.get("name"), d.get("address"), d.get("type")))
    for r, ds in rooms.items():
        print(f"  [{r}] " + ", ".join(f"{n}(addr={a},type={t})" for n, a, t in ds))
    mk = fetch_mesh_key()
    print("meshKey:", mk.hex())
    c = Codec(home["key4"].to_bytes(4, "big"), mk)
    for seq in (1, 2):
        b = c.encode(head(seq), cmd_group_switch(1, on=False))
        r, out = c.decode(b)
        print(f"  round-trip seq={seq}: ret={hex(r)} head={out[:4].hex()} data={out[4:16].hex()}")
