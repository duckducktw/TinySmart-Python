#!/usr/bin/env python3
"""
TinySmart Controller — 由 QR Code 解碼驅動燈控（群組/房間 + 個別燈：開關 / 亮度 / 色溫）
====================================================================================
逆向對象：com.iot.tinysmart（Flutter / Dart 3.3.4）＋ libtinysmartencode.so
所有關鍵參數皆由靜態逆向 + 實機驗證取得，非猜測。

用法
----
  # 1) 解 QR（FTDSF|2|<base64>）
  python3 tinysmart_controller.py qr "FTDSF|2|<BASE64>..."
  python3 tinysmart_controller.py qr --image /path/qrcode.png

  # 2) 解 QR → 打 API 取「房間 / 燈具清單」（分享 API，免簽章）
  python3 tinysmart_controller.py share <shareId> [--member-id <id>]

  # 3) 個別燈控制（預設 dry-run：只印出要送的 31-byte 框，不連 BLE）
  python3 tinysmart_controller.py ctrl --mac AA:BB:CC:DD:EE:FF --addr 1 --on
  python3 tinysmart_controller.py ctrl --mac ... --addr 1 --brightness 80
  python3 tinysmart_controller.py ctrl --mac ... --addr 1 --cct 50
  python3 tinysmart_controller.py ctrl --mac ... --addr 1 --on --send   # 真的送出

  # 4) 房間/群組控制（同一房間的多顆燈 → 逐顆送框）
  python3 tinysmart_controller.py room --name 全屋照明 --on

相依： pip install pycryptodome requests bleak unicorn pyelftools
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, struct, sys, time

# ============================================================== 已知常數 ======
QR_PREFIX = "FTDSF"
QR_KEY = bytes.fromhex("1a2c3b161819a6e7954623a7d6e8e116")   # libapp.so pp+0x47b80
QR_IV  = b"ftd95279527a2c3c"                                  # libapp.so pp+0x49c60

CLOUD_SHARE_BASE = "https://flashsmart.icoding.net.cn/flashsmart/"   # 免簽章
CLOUD_IOT_BASE   = "https://iotmgmt.fentengda.com/api/"              # 需 Signature

# 簽章（IotRequestHeaderUtil.getSignature；已對實機 logcat 兩次驗證吻合）
SIG_A = "3e0621ebccef"                          # pp+0x4c4a8
SIG_B = "Ryfpjcrq58uS8XgWrkqkrT4YD78r4JyX"      # 實測反推 + sha256 前16hex 驗證

# BLE（easysmart01 GattRemakeUtil）
BLE_SERVICE = "0000FFE0-D8A9-E658-87EF-A96719815D7B"
BLE_CHAR_FFE2 = "0000FFE2-D8A9-E658-87EF-A96719815D7B"
BLE_CHAR_FFE3 = "0000FFE3-D8A9-E658-87EF-A96719815D7B"

# opcode（desc[7]）— 由 native control* 逐一抽取（見 ANALYSIS_REPORT.md）
OP_ON, OP_OFF = 0x10, 0x11
OP_BRIGHTNESS, OP_CCT, OP_NIGHT, OP_RGB = 0x20, 0x21, 0x23, 0x40
DEFAULT_KEY4 = 0x57821A6D     # etype=0 用的內建 key


# ============================================================== QR 加解密 =====
class QrCodec:
    """FTDSF share-QR：AES-128-CBC / PKCS7。已對兩張樣本驗證。"""

    @staticmethod
    def decrypt(qr_string: str) -> dict:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        parts = qr_string.strip().split("|")
        if len(parts) != 3 or parts[0] != QR_PREFIX:
            raise ValueError(f"非 {QR_PREFIX} QR：{qr_string[:32]!r}")
        ct = base64.b64decode(parts[2])
        pt = unpad(AES.new(QR_KEY, AES.MODE_CBC, QR_IV).decrypt(ct), 16)
        data = json.loads(pt.decode("utf-8"))
        return {"version": int(parts[1]), **data}

    @staticmethod
    def encrypt(payload: dict, version: int = 2) -> str:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        ct = AES.new(QR_KEY, AES.MODE_CBC, QR_IV).encrypt(pad(raw, 16))
        return f"{QR_PREFIX}|{version}|" + base64.b64encode(ct).decode()

    @staticmethod
    def decrypt_image(path: str) -> dict:
        """從 QR 圖片解（需要 opencv-python；純解碼不必開相機）。"""
        import cv2
        img = cv2.imread(path)
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        if not data:
            raise RuntimeError("圖片中找不到 QR")
        return QrCodec.decrypt(data)


# ============================================================== 雲端 API ======
class Signature:
    @staticmethod
    def sign(timestamp: int | None = None) -> str:
        ts = int(time.time()) if timestamp is None else timestamp
        p1 = hashlib.sha256(f"{SIG_A},{SIG_B},{ts}".encode()).hexdigest()[:16]
        return base64.b64encode(f"{SIG_A},{ts},{p1}".encode()).decode()


class Api:
    """分享 API（免簽章）＋ IoT API（帶 Signature）。body 一律 base64(JSON)。"""

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    @staticmethod
    def _body(obj) -> str:
        return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()

    def _post(self, url: str, obj, *, signed: bool, slash: bool = False):
        """POST；先試 requests，失敗改用 curl（部分環境 IPv6/代理會卡）。"""
        body = self._body(obj)
        full = url + ("/" if slash else "")
        headers = {"Content-Type": "application/json;charset=utf-8"}
        if signed:
            headers["Signature"] = Signature.sign()
        raw = None
        try:
            import requests
            r = requests.post(full, data=body, headers=headers, timeout=self.timeout)
            raw = r.text
        except Exception:
            import subprocess
            cmd = ["curl", "-s", "-X", "POST", full, "--max-time", str(int(self.timeout)), "-d", body]
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]
            raw = subprocess.run(cmd, capture_output=True, text=True).stdout
        try:
            j = json.loads(raw)
        except Exception:
            raise RuntimeError(f"bad response: {str(raw)[:200]}")
        data = j.get("data", "")
        if isinstance(data, str) and data:
            try:
                data = json.loads(base64.b64decode(data).decode("utf-8"))
            except Exception:
                pass
        return j, data

    # ---- 分享（免簽章）----
    def query_share(self, share_id: str, member_id: str | int = "1"):
        """QR 解出的 shareID → 回傳分享的家庭/燈具資訊。"""
        j, d = self._post(CLOUD_SHARE_BASE + "queryShareInfo",
                          {"shareId": share_id, "memberId": str(member_id)}, signed=False)
        return j, d

    def create_share(self, share_device_json: str, **kw):
        params = {"shareDeviceJson": share_device_json, "shareType": kw.get("shareType", 1),
                  "shareLimitTime": kw.get("shareLimitTime", ""),
                  "controlExpirationTime": kw.get("controlExpirationTime", ""),
                  "qrCodeExpirationTime": kw.get("qrCodeExpirationTime", "")}
        params.update({k: v for k, v in kw.items() if k in ("memberId", "homeId", "userId")})
        j, d = self._post(CLOUD_SHARE_BASE + "createShareInfo", params, signed=False)
        return j, d

    # ---- IoT（帶簽章）----
    def skylight_config(self):
        return self._post(CLOUD_IOT_BASE + "skylight/configList", {}, signed=True, slash=True)


# ============================================================== BLE 框 ========
class NativeEmu:
    """Unicorn 載入 libtinysmartencode.so，取得 byte-exact 的 encode/decode。"""

    def __init__(self, so_path: str):
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL
        from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_LR
        from elftools.elf.elffile import ELFFile
        so = open(so_path, "rb")
        elf = ELFFile(so)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mapped = set()
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            va, ms = seg["p_vaddr"], seg["p_memsz"]
            base = va & ~0xFFF
            end = (va + ms + 0xFFF) & ~0xFFF
            p = base
            while p < end:
                if p not in mapped:
                    self.uc.mem_map(p, 0x1000, UC_PROT_ALL)
                    mapped.add(p)
                p += 0x1000
            self.uc.mem_write(va, seg.data())
        self.uc.mem_map(0x10000000, 0x100000, UC_PROT_ALL)   # stack
        self.uc.mem_map(0x30000000, 0x100000, UC_PROT_ALL)   # heap
        self.uc.mem_map(0x40000000, 0x10000, UC_PROT_ALL)    # TLS
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x40000000)
        self.STACK, self.HEAP = 0x10000000, 0x30000000
        self.rand_val = 0
        from unicorn import UC_HOOK_CODE
        self.uc.hook_add(UC_HOOK_CODE, self._hook)

    def _hook(self, uc, addr, size, ud):
        from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_LR
        if addr == 0x90F0:                 # rand@plt
            uc.reg_write(UC_ARM64_REG_X0, self.rand_val)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        elif addr in (0x90B0, 0x90C0, 0x90D0, 0x90E0, 0x9100):
            uc.reg_write(UC_ARM64_REG_X0, 0x30000000)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _run(self, fn, args):
        from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC
        uc = self.uc
        sp = self.STACK + 0x80000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_LR, 0xDEADBEEF)
        for i, a in enumerate(args):
            uc.reg_write([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2][i], a)
        uc.emu_start(fn, 0xDEADBEEF, count=300000)
        return uc.reg_read(UC_ARM64_REG_X0)

    def encode(self, desc: bytes, key4: int, rand_byte: int) -> bytes:
        assert len(desc) == 0x16
        self.rand_val = rand_byte
        d = self.HEAP + 0x1000; o = self.HEAP + 0x2000; n = self.HEAP + 0x3000
        self.uc.mem_write(d, desc)
        self.uc.mem_write(n, b"\x00\x00\x00\x00")
        self._run(0x889C, [d, o, n])
        ln = struct.unpack("<I", self.uc.mem_read(n, 4))[0]
        return bytes(self.uc.mem_read(o, ln))

    def decode(self, frame: bytes, key4: int) -> bytes:
        self.rand_val = 0
        d = self.HEAP + 0x1000; o = self.HEAP + 0x2000
        self.uc.mem_write(d, frame)
        self.uc.mem_write(o, b"\x00" * 0x40)
        self._run(0x8D3C, [d, 31, o])
        return bytes(self.uc.mem_read(o, 0x16))


class Frame:
    """31-byte TinySmart 框： [02 01 02 1b03f8f2][desc 0x16][rand][crc16] → XOR/CRC/位元重排"""

    def __init__(self, emu: NativeEmu, session_key4: int = DEFAULT_KEY4):
        self.emu = emu
        self.session_key4 = session_key4

    @staticmethod
    def desc(opcode: int, addr: int, data: bytes = b"", etype: int = 1) -> bytes:
        d = bytearray(0x16)
        d[0] = (etype << 4) | 0x80
        d[1] = (addr >> 8) & 0xFF
        d[2] = addr & 0xFF
        d[7] = opcode & 0xFF
        if data:
            d[3:3 + len(data)] = data[:0x13]
        return bytes(d)

    def build(self, opcode: int, addr: int, data: bytes = b"", *, etype: int = 1,
              rand_byte: int | None = None) -> bytes:
        rb = int.from_bytes(os.urandom(1), "big") if rand_byte is None else rand_byte
        key = self.session_key4 if etype == 1 else DEFAULT_KEY4
        return self.emu.encode(self.desc(opcode, addr, data, etype), key, rb)

    def parse(self, frame: bytes, etype: int = 1) -> bytes:
        key = self.session_key4 if etype == 1 else DEFAULT_KEY4
        return self.emu.decode(frame, key)


def find_so(path: str) -> str | None:
    """從 APK / 目錄 / .so 找出 libtinysmartencode.so (arm64)。"""
    import zipfile
    if path.endswith(".so") and os.path.exists(path):
        return path
    if os.path.isdir(path):
        for root, _d, files in os.walk(path):
            for fn in files:
                if fn == "libtinysmartencode.so" and "arm64" in root:
                    return os.path.join(root, fn)
        return None
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith("arm64-v8a/libtinysmartencode.so"):
                    dst = "/tmp/libtinysmartencode.so"
                    open(dst, "wb").write(z.read(n))
                    return dst
    except Exception:
        return None
    return None


# ============================================================== 控制器 ========
class TinySmartController:
    def __init__(self, so_path: str | None = None, session_key4: int = DEFAULT_KEY4):
        self.api = Api()
        self.emu = None
        if so_path is None:
            for c in (os.environ.get("TINYSMART_APK", ""), "/tmp/libtinysmartencode.so",
                      os.path.expanduser("~/Downloads/tiny_smart.apk"),
                      os.path.expanduser("~/Data/Dev/Android/tinysmart/tiny_smart.apk")):
                if c and os.path.exists(c):
                    so_path = find_so(c)
                    if so_path:
                        break
        if so_path:
            self.emu = NativeEmu(so_path)
            self.frame = Frame(self.emu, session_key4)
        else:
            self.frame = None

    # ---- 1) QR ----
    def decrypt_qr(self, qr_string: str) -> dict:
        return QrCodec.decrypt(qr_string)

    # ---- 2) 房間 / 燈具（由 QR 的 shareID 走 API）----
    def share_devices(self, share_id: str, member_id: str | int = "1"):
        j, data = self.api.query_share(share_id, member_id)
        return j, data

    def share_home(self, share_id: str, member_id: str | int = "1") -> dict:
        """QR 的 shareID → {home, rooms, devices, key4, scenes}

        shareDeviceJson（base64）內含 home.bleCode(=4-byte session key)、
        devices[].mac / address(mesh addr) / roomName —— 已對實機 9 燈 3 房驗證。
        """
        j, d = self.api.query_share(share_id, member_id)
        if j.get("resultCode") != "Success":
            raise RuntimeError(f"queryShareInfo 失敗: {d}")
        mi = d.get("memberInfo", {})
        raw = mi.get("shareDeviceJson")
        sd = json.loads(base64.b64decode(raw).decode()) if raw else {}
        home = sd.get("home", {})
        key4 = None
        if home.get("bleCode"):
            key4 = int.from_bytes(base64.b64decode(home["bleCode"])[:4], "big")
        for dev in sd.get("devices", []):
            if dev.get("mac"):
                dev["mac_clean"] = dev["mac"].rstrip(":")     # App 的 mac 尾端帶 ':'
        return {"home": home, "rooms": sd.get("rooms", []), "devices": sd.get("devices", []),
                "scenes": sd.get("scenes", []), "floors": sd.get("floors", []),
                "key4": key4, "memberInfo": mi}

    def from_qr(self, qr_string: str, member_id: str | int = "1") -> dict:
        """一行搞定：QR 字串 → 家庭/房間/燈具/key（並自動套用 session key）。"""
        info = self.decrypt_qr(qr_string)
        home = self.share_home(info["shareID"], member_id)
        home["shareID"] = info["shareID"]
        if home.get("key4") and self.emu:
            self.frame.session_key4 = home["key4"]
        return home

    def rooms_of(self, home: dict) -> dict:
        """{房間名: [裝置, ...]}"""
        out = {}
        for d in home.get("devices", []):
            out.setdefault(d.get("roomName") or "未分房", []).append(d)
        return out

    # ---- 3) 個別燈控制 ----
    def commands(self, *, on=None, brightness=None, cct=None, night=None):
        """回傳 [(opcode, data), ...]；亮度 0-100、色溫 0-100。"""
        out = []
        if on is not None:
            out.append((OP_ON if on else OP_OFF, b""))
        if brightness is not None:
            out.append((OP_BRIGHTNESS, bytes([int(brightness) & 0xFF])))
        if cct is not None:
            out.append((OP_CCT, bytes([int(cct) & 0xFF])))
        if night is not None:
            out.append((OP_NIGHT, bytes([1 if night else 0])))
        return out

    def build_light_frames(self, addr: int, **kw):
        return [self.frame.build(op, addr, data) for op, data in self.commands(**kw)]

    async def send(self, mac: str, frames, char_uuid: str = BLE_CHAR_FFE3):
        from bleak import BleakClient
        async with BleakClient(mac) as cli:
            for f in frames:
                await cli.write_gatt_char(char_uuid, f, response=False)
                time.sleep(0.15)

    # ---- 4) 房間 / 群組控制 ----
    def build_room_frames(self, devices, **kw):
        """devices = [{'name':..., 'addr':int}, ...] → {name: [frames]}"""
        return {d["name"]: self.build_light_frames(int(d["addr"]), **kw) for d in devices}


# ============================================================== CLI ===========
def _main(argv=None):
    p = argparse.ArgumentParser(description="TinySmart 燈控（QR 解碼 → 房間/個別燈）")
    p.add_argument("--so", help="libtinysmartencode.so 或 APK 路徑")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("qr", help="解 FTDSF QR")
    q.add_argument("value", nargs="?", help="FTDSF|2|<base64>")
    q.add_argument("--image", help="QR 圖片路徑")

    s = sub.add_parser("share", help="QR 的 shareID → 房間/燈具清單")
    s.add_argument("share_id")
    s.add_argument("--member-id", default="1")

    c = sub.add_parser("ctrl", help="個別燈控制")
    c.add_argument("--mac"); c.add_argument("--addr", type=int)
    c.add_argument("--qr", help="FTDSF QR 字串（自動解析 mac/addr/key）")
    c.add_argument("--image", help="QR 圖片")
    c.add_argument("--device", help="燈具名稱（配合 --qr 自動找 mac/addr）")
    c.add_argument("--on", action="store_true"); c.add_argument("--off", action="store_true")
    c.add_argument("--brightness", type=int, help="0-100")
    c.add_argument("--cct", type=int, help="色溫 0-100")
    c.add_argument("--night", type=int, choices=[0, 1])
    c.add_argument("--send", action="store_true", help="真的送出（預設 dry-run）")

    r = sub.add_parser("room", help="房間控制（QR 自動解析該房所有燈）")
    r.add_argument("--qr", help="FTDSF QR 字串")
    r.add_argument("--image", help="QR 圖片")
    r.add_argument("--room", help="房間名（例：客廳）")
    r.add_argument("--name", help="別名，同 --room")
    r.add_argument("--devices", help="JSON: [{\"name\":..,\"mac\":..,\"addr\":..}]（不給 QR 時用）")
    r.add_argument("--on", action="store_true"); r.add_argument("--off", action="store_true")
    r.add_argument("--brightness", type=int); r.add_argument("--cct", type=int)
    r.add_argument("--send", action="store_true")

    h = sub.add_parser("home", help="QR → 房間/燈具清單")
    h.add_argument("--qr"); h.add_argument("--image")
    h.add_argument("--member-id", default="1")

    a = p.parse_args(argv)
    ctl = TinySmartController(a.so)

    def _qr_text():
        return QrCodec.decrypt_image(a.image) if getattr(a, "image", None) else None

    if a.cmd == "qr":
        data = QrCodec.decrypt_image(a.image) if a.image else QrCodec.decrypt(a.value)
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif a.cmd == "home":
        qs = open(a.qr).read().strip() if a.qr and os.path.exists(a.qr) else a.qr
        if a.image:
            info = _qr_text(); qs = None
            home = ctl.share_home(info["shareID"], a.member_id)
        else:
            home = ctl.from_qr(qs, a.member_id)
        print(f"home: {home['home'].get('homeName')}  key4=0x{(home.get('key4') or 0):08X}")
        for room, devs in ctl.rooms_of(home).items():
            print(f"\n[{room}]  {len(devs)} 顆")
            for d in devs:
                print(f"   {d.get('name'):<14} mac={d.get('mac_clean')}  addr={d.get('address')}")
    elif a.cmd == "share":
        j, d = ctl.share_devices(a.share_id, a.member_id)
        print(json.dumps({"result": j, "data": d}, ensure_ascii=False, indent=2)[:4000])
    elif a.cmd == "ctrl":
        mac, addr = a.mac, a.addr
        if a.qr or a.image:
            info = _qr_text() if a.image else ctl.decrypt_qr(a.qr)
            home = ctl.share_home(info["shareID"], "1")
            if home.get("key4"):
                ctl.frame.session_key4 = home["key4"]
            if a.device:
                hit = [d for d in home["devices"] if a.device in (d.get("name") or "")]
                if not hit:
                    sys.exit(f"找不到燈具 {a.device!r}")
                mac, addr = hit[0]["mac_clean"], int(hit[0]["address"])
                print(f"# 解析：{hit[0]['name']} mac={mac} addr={addr} key4=0x{home['key4']:08X}")
        if not mac or addr is None:
            sys.exit("需要 --mac/--addr 或 --qr + --device")
        frames = ctl.build_light_frames(addr, on=True if a.on else (False if a.off else None),
                                        brightness=a.brightness, cct=a.cct, night=a.night)
        for f in frames:
            print("frame:", f.hex())
        if a.send:
            import asyncio
            asyncio.run(ctl.send(mac, frames))
            print("sent ->", mac)
        else:
            print("[dry-run] 未送出；加 --send 才會真的送 BLE")
    elif a.cmd == "room":
        devs = json.loads(a.devices) if a.devices else []
        if a.qr or a.image:
            info = _qr_text() if a.image else ctl.decrypt_qr(a.qr)
            home = ctl.share_home(info["shareID"], "1")
            if home.get("key4"):
                ctl.frame.session_key4 = home["key4"]
            rn = a.room or a.name
            if rn:
                devs = [{"name": d["name"], "mac": d["mac_clean"], "addr": int(d["address"])}
                        for d in home["devices"] if d.get("roomName") == rn]
                print(f"# 房間 {rn}：{len(devs)} 顆，key4=0x{home['key4']:08X}")
            else:
                devs = [{"name": d["name"], "mac": d["mac_clean"], "addr": int(d["address"])}
                        for d in home["devices"]]
        if not devs:
            sys.exit("需要 --qr + --room 或 --devices")
        frames = ctl.build_room_frames(devs, on=True if a.on else (False if a.off else None),
                                       brightness=a.brightness, cct=a.cct)
        for dev in devs:
            print(f"{dev['name']}: " + " ".join(f.hex() for f in frames[dev["name"]]))
        if a.send:
            import asyncio
            for d in devs:
                asyncio.run(ctl.send(d["mac"], frames[d["name"]]))
                print("sent ->", d["name"])
        else:
            print("[dry-run] 未送出；加 --send 才會真的送 BLE")


if __name__ == "__main__":
    _main()
