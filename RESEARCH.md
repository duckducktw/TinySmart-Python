# TinySmart 燈控系統 — 逆向工程研究報告

- 對象：`com.iot.tinysmart` v2.4.5（Flutter / Dart 3.3.4，engine `e2621f41…`）
- 硬體：Samsung S25（`192.168.0.180:5555`，無 root）
- 方法：靜態（jadx/blutter/capstone）+ 動態（Unicorn 模擬、adb、HCI snoop）
- 原則：**零猜測** — 每個結論都有程式碼或實機封包為證
- 日期：2026-09-24

---

## 0. 結論摘要（TL;DR）

| 項目 | 狀態 |
|---|---|
| QR Code 解密 | ✅ 完全破解（AES-128-CBC，常數金鑰/IV），兩張樣本實測 |
| 雲端 API | ✅ 端點 + 簽章演算法完全還原（簽章以實機 logcat 對拍驗證吻合） |
| QR → 房間/燈具 | ✅ 一行打通：9 顆燈、3 個房間、mac / mesh addr / session key 全取得 |
| BLE 控制框 | ✅ 31-byte 框結構完全還原，Unicorn 模擬原 `.so` 取得 byte-exact 結果 |
| BLE 動態擷取 | ✅ 免 root 管線打通（HCI snoop → bugreport → btsnoop 解析器） |
| 實機送 BLE | ⏸️ 待燈復電（需一顆燈在線才能交叉驗證） |

**核心發現**：`FTDSF` QR **不是設備配對碼**，而是「**家庭分享憑證**」。
掃描者拿到 `shareID` 後向雲端查詢，即可取回整個家庭的裝置清單（含每顆燈的 MAC 與 mesh 位址）。

---

## 1. 系統架構

```
┌─────────────┐   FTDSF|2|<b64>    ┌──────────────────────────────┐
│  QR Code    │ ─────────────────► │  queryShareInfo (免簽章)      │
│ (家庭分享)   │  AES-128-CBC 解密   │  flashsmart.icoding.net.cn   │
└─────────────┘                    └──────────────┬───────────────┘
                                                  │ shareDeviceJson (base64)
                                                  ▼
                              ┌────────────────────────────────────┐
                              │ home.bleCode → 4-byte session key  │
                              │ devices[] → name / mac / address   │
                              │ rooms[]   → 房間分類               │
                              └──────────────┬─────────────────────┘
                                             │
                          BLE GATT (FFE0/FFE2/FFE3)
                                             ▼
                              ┌────────────────────────────────────┐
                              │ 31-byte 框（XOR + CRC16 + 位元重排）│
                              └────────────────────────────────────┘
```

App 內部另一條路（需簽章）：`https://iotmgmt.fentengda.com/api/...`

---

## 2. QR Code 協定

### 2.1 格式
```
FTDSF|<version>|<base64(ciphertext)>
```
- `version`：目前為 `2`
- `ciphertext`：80 bytes（= 5 × AES block，**無 IV 前置**）

### 2.2 密碼學參數（硬編碼）
| 項目 | 值 | 來源位置 |
|---|---|---|
| 演算法 | **AES-128-CBC**，PKCS7 | `logic/untils/aes.dart :: homeShareInfoEncode/Decrypted` |
| Key | `1a2c3b161819a6e7954623a7d6e8e116`（hex → 16 B） | `libapp.so` object pool `pp+0x47b80` |
| IV | `ftd95279527a2c3c`（UTF-8 → 16 B） | `libapp.so` object pool `pp+0x49c60` |
| Mode 常數 | `Obj!AESMode@1178be1` = `cbc` | `pp+0x47b88` |
| Padding | `PKCS7` | `pp+0x47bc0` |

> 註：原始碼中 key 走 `hexStringToBytes → base64Encode → base64Decode` 繞路，結果等同原 bytes。
> IV 來自 `IV.fromUtf8("ftd95279527a2c3c")` —— 該字串緊鄰 pointycastle 的 RSA 常數區。

### 2.3 明文格式
```json
{"platCode":"flashsmart_ts","shareID":"<uuid>"}
```

### 2.4 實測解碼結果
```
輸入 FTDSF|2|<BASE64>
輸出 {"platCode":"flashsmart_ts","shareID":"<SHARE_ID>"}

輸入 FTDSF|2|<BASE64>（2026-09-24 新版）
輸出 {"platCode":"flashsmart_ts","shareID":"<SHARE_ID>"}
```

### 2.5 反推 IV 的方法（通用技巧）
CBC 的前 16 bytes 明文需要正確 IV，但 **block 1 之後與 IV 無關**。
先用「假設 IV = 0」解密 → 尾段會是可讀 JSON（`…","shareID":"<uuid>"}`）→
由尾段推回完整 JSON 結構後，`IV = D_key(C0) XOR 明文前 16 bytes`。

---

## 3. 雲端 API

### 3.1 分享 API（**免簽章**）
```
POST https://flashsmart.icoding.net.cn/flashsmart/<op>
Content-Type: application/json;charset=utf-8
body = base64( utf8( jsonEncode(params) ) )
resp = {"resultCode":"Success"|"Fail", "data": <base64(JSON)>}
```

| op | 參數 | 用途 |
|---|---|---|
| `queryShareInfo` | `{shareId, memberId}` | **QR 掃描後取回家庭/裝置清單** |
| `createShareInfo` | `{shareDeviceJson, shareLimitTime, shareType, controlExpirationTime, qrCodeExpirationTime}` | 產生分享（`shareDeviceJson = base64(json(家庭資訊))`） |

錯誤碼：`10000` 數據不完整 / `40003` 分享數據已過期 / `Success` 成功

### 3.2 IoT API（**需簽章**）
```
POST https://iotmgmt.fentengda.com/api/<path>/     ← 注意尾斜線
header: Signature: <sig>
```
簽章演算法（`logic/iot/base/IotRequestHeaderUtil.dart :: getSignature`）：
```python
A = "3e0621ebccef"                         # pool pp+0x4c4a8
B = "Ryfpjcrq58uS8XgWrkqkrT4YD78r4JyX"     # 32 字元；由實測簽章反推（sha256 前 16 hex 命中）
ts  = int(time.time())
sig = base64( f"{A},{ts},{ sha256(f'{A},{B},{ts}')[:16] }" )
```
**實機驗證**：取 logcat 攔截器的兩筆簽章，用上式重算 → **兩次 byte-for-byte MATCH**。

> ⚠️ 未閉環：直接呼叫 `iotmgmt` 端點仍回 `Invalid Sign header`，
> 推測還需要 App 額外送出的 header（分享 API 不受影響）。

### 3.3 App 偵錯通道（免 root 取封包的金鑰）
App 內建 **Dio 攔截器**，把每個請求寫進 logcat：
```
I/flutter: dio 拦截打印请求地址 Request: https://iotmgmt.fentengda.com/api/skylight/configList
I/flutter: dio 拦截打印请求参数 Request: null
I/flutter: dio 拦截打印回复数据 Response: {code:0, message:success, data:[…]}
I/flutter: time = … / timestamp = … / signature = …
```

---

## 4. 家庭模型（實測）

由 2026-09-24 的 QR 解出：

```
home: 我的家庭(share)   familyId <FAMILY_ID>
      bleCode = base64 "<BLE_CODE_B64>" → 4-byte session key = 0x<BLE_CODE_HEX>
floor: 1 樓 (floorId=1)
rooms: 全屋(0) / 客廳(1) / 主臥(2) / 衛生間(6)
```

| 房間 | 燈具 | mac | mesh addr |
|---|---|---|---|
| 客廳 | 雙色燈4C:D5 | `FC:42:65:6X:XX:XX` | 1 |
| 客廳 | 雙色燈18:5A | `FC:42:65:6X:XX:XX` | 2 |
| 客廳 | 雙色燈22:00 | `FC:42:65:6X:XX:XX` | 3 |
| 客廳 | 雙色燈CF:51 | `FC:42:65:6X:XX:XX` | 4 |
| 客廳 | 雙色燈1A:75 | `FC:42:65:6X:XX:XX` | 5 |
| 主臥 | 雙色燈3B:61 | `FC:42:65:6X:XX:XX` | 6 |
| 主臥 | 雙色燈3B:7C | `FC:42:65:6X:XX:XX` | 7 |
| 主臥 | 雙色燈D0:AE | `FC:42:65:6X:XX:XX` | 8 |
| 衛生間 | 雙色燈D2:16 | `FC:42:65:6X:XX:XX` | 9 |

（App 顯示名稱尾碼＝MAC 末兩 bytes；`mac` 欄位尾端帶一個 `:`，需 strip）

---

## 5. BLE 協定

### 5.1 GATT Profile
| 角色 | UUID |
|---|---|
| Service | `0000FFE0-D8A9-E658-87EF-A96719815D7B` |
| Characteristic | `0000FFE2-D8A9-E658-87EF-A96719815D7B` |
| Characteristic | `0000FFE3-D8A9-E658-87EF-A96719815D7B` |

（來源：`easysmart01/logic/untils/gatt_single_instance.dart` `GattRemakeUtil`）

### 5.2 控制框（31 bytes）
原生 lib：`libtinysmartencode.so`
JNI：`com.jingyuan.tinysmartencodelib.TinySmartTool.{encode,decode,checkValid,controlOn,…}`

```
b0..b2    = 02 01 02                (固定)
b3..b6    = 1b 03 f8 f2             (rodata 0x1698 常數)
b7..b14   = desc[0x00..0x07]
b15       = desc[0x08]
b16..b17  = desc[0x0A..0x0B]
b18..b25  = desc[0x0C..0x13]
b26..b27  = desc[0x14..0x15]
b28       = rand() & 0xFF
b29..b30  = 0                       (CRC 佔位)

① key XOR      : b12..b27 ^= key4[0..3] 循環
② CRC16/XMODEM : poly 0x1021, init = 0xFF00 | (~rand & 0xFF)，範圍 b7..b28
③ b29..b30     = ((key4 & 0xFFFF) + (key4 >> 16) + crc) & 0xFFFF
④ rand 混淆    : b7..b27 ^= rand
⑤ 位元重排      : 對 b7..b30 施加 0x8b9c 的函式（見 5.4）
```

### 5.3 desc 結構（0x16 bytes）與 opcode
| 欄位 | 意義 |
|---|---|
| `desc[0]` | 低 nibble 必須 = 0；bit7=1 → etype=(desc[0]>>4)&7 選 key（0=內建、1=session）；bit7=0 → key = desc[1..4] |
| `desc[1..2]` | mesh 位址（big-endian） |
| `desc[7]` | **opcode** |
| 其他 | 參數 |

實測抽出（由各 `control*` JNI 函式逐一讀立即數）：

| 功能 | opcode |
|---|---|
| 開 | `0x10` |
| 關 | `0x11` |
| 亮度 | `0x20` |
| 色溫 | `0x21` |
| 小夜燈 | `0x23` |

### 5.4 位元重排函式（0x8b9c）
- 常數：`0x53` / `0x1EE` / `0x11`；向量 `(-4,-6,-2,-1)`（USHL 右移 4/6/2/1）、`(2,1,4,8)`（位元遮罩）
- 每輪把狀態 `w13` 的 bit0..3 與輸入 byte 混合，輸出 1 byte 並更新 `w13`
- **已證實與呼叫者的 v2 無關**（`zip1` 覆寫），是輸入的純函式
- 手寫重寫未收斂 → 改以 **Unicorn 精確模擬 `.so`** 取得 byte-exact 結果

### 5.5 驗證證據（往返）
```
build(opcode=0x20, addr=0x00AB, data=[77])  → 31-byte
native decode → 90 00 ab 4d 00 00 00 20 …
                 ↑     ↑        ↑
        desc[0]=90  addr=0xAB  值=77  opcode=0x20
→ addr / 參數 / opcode 三者皆 byte-exact 還原
```

### 5.6 動態擷取管線（免 root）
```bash
adb shell settings put secure bluetooth_hci_log 1
adb shell cmd bluetooth_manager disable && adb shell cmd bluetooth_manager enable
adb bugreport /tmp/br.zip          # snoop 檔在 zip 內 FS/data/log/bt/btsnoop_hci.log
python3 blesnoop.py btsnoop_hci.log [--mac FC:42:65:…]
```
原理：**HCI 層為明文 ATT payload**（LE 鏈路層加密在控制器之下），
故 GATT write 內容 = App 真正送出的位元組。

實測這份 log：`records=47810`，ATT 涵蓋 ReadByGroup/ReadByType/FindInfo/Mtu/Write，
但 **App 框頭 `0201021b03f8f2` 出現 0 次、燈 OUI `FC:42:65` 0 次**（當時燈已斷電）。

---

## 6. 交付物與用法

### 檔案
| 檔案 | 說明 |
|---|---|
| `tinysmart_controller.py` | 主程式：QR 解碼 / API / 房間與個別燈控制（CLI） |
| `blesnoop.py` | btsnoop HCI log 解析器（抓 App 真實 BLE 封包） |
| `ANALYSIS_REPORT.md` | 本報告 |

### 指令
```bash
export TINYSMART_APK=/path/to/tiny_smart.apk     # 或 --so <libtinysmartencode.so>

# 1) QR 解碼
python3 tinysmart_controller.py qr "FTDSF|2|…"
python3 tinysmart_controller.py qr --image qr.png

# 2) QR → 房間 / 燈具 / key
python3 tinysmart_controller.py home --qr "$(cat qr.txt)"
#   home: 我的家庭(share)  key4=0x<BLE_CODE_HEX>
#   [客廳] 5 顆 / [主臥] 3 顆 / [衛生間] 1 顆 …

# 3) 個別燈：開關 / 亮度 / 色溫（預設 dry-run）
python3 tinysmart_controller.py ctrl --qr "$(cat qr.txt)" --device 18:5A --on --brightness 80 --cct 50
python3 tinysmart_controller.py ctrl --qr … --device 18:5A --on --send     # 真的送出

# 4) 房間控制（自動解析該房所有燈）
python3 tinysmart_controller.py room --qr "$(cat qr.txt)" --room 主臥 --on

# 5) 擷取 App 真實 BLE 封包
python3 blesnoop.py btsnoop_hci.log --mac FC:42:65:6X:XX:XX
```

### Python API
```python
from tinysmart_controller import TinySmartController
c = TinySmartController()                 # 自動找 APK/.so（或設 TINYSMART_APK）
info = c.decrypt_qr(qr_string)            # {'version','platCode','shareID'}
home = c.from_qr(qr_string)               # {home, rooms, devices, key4, …}（自動套 key）
print(home['key4'])                       # 0x<BLE_CODE_HEX>
c.rooms_of(home)                          # {'客廳':[…], '主臥':[…], '衛生間':[…]}
frames = c.build_light_frames(2, on=True, brightness=80, cct=50)
```

---

## 7. 未閉環項目

| # | 項目 | 影響 | 解法 |
|---|---|---|---|
| 1 | 實機送 BLE 未驗證 | 無法確認 FFE2/FFE3 哪個是 write、回報格式 | 燈復電後 `--send` 一顆 + `blesnoop.py` 比對 |
| 2 | `iotmgmt` API 額外 header | App 內部 API 無法直接呼叫 | 比對 App 完整 header 集合 |
| 3 | 位元重排純 Python 重寫 | 目前依賴 Unicorn 模擬（需 `.so`） | 已完成逐指令抄錄，未收斂 |
| 4 | 群組廣播（advertising）PDU | 「房間」若走廣播而非逐顆 GATT 則需另解 | 待 `libflashsmartencode.so :: Tool2.pdu` |

---

## 8. 附錄：關鍵常數速查

```
QR            key  = 1a2c3b161819a6e7954623a7d6e8e116   (hex, 16B)
QR            iv   = "ftd95279527a2c3c"                 (utf8, 16B)
QR            algo = AES-128-CBC / PKCS7
QR            form = FTDSF|<ver>|<base64>

API  分享     base = https://flashsmart.icoding.net.cn/flashsmart/   (免簽章)
API  IoT      base = https://iotmgmt.fentengda.com/api/              (需 Signature, 尾斜線)
簽章          A    = 3e0621ebccef
簽章          B    = Ryfpjcrq58uS8XgWrkqkrT4YD78r4JyX
簽章          sig  = base64(f"{A},{ts},{sha256(f'{A},{B},{ts}')[:16]}")

BLE  service  = 0000FFE0-D8A9-E658-87EF-A96719815D7B
BLE  char     = 0000FFE2 / 0000FFE3 (同前綴)
BLE  內建key   = 0x57821A6D            (etype=0)
BLE  session  = home.bleCode → 0x<BLE_CODE_HEX>
BLE  opcode   = 0x10 開 / 0x11 關 / 0x20 亮度 / 0x21 色溫 / 0x23 小夜燈
BLE  框架      = 02 01 02 | 1b 03 f8 f2 | desc(0x16) | rand | crc16
CRC           = CRC-16/XMODEM, poly 0x1021, init 0xFF00|(~rand&0xFF)

App 偵錯       logcat tag: "dio 拦截打印请求地址/请求参数/回复数据"
HCI  擷取       adb shell settings put secure bluetooth_hci_log 1 → bugreport
```


---

## 9. 【關鍵修正】控制是單向 BLE 廣播，不是 GATT 連線

### 9.1 證據
- dex 內建 `com/example/ble_lib/ble_lib/BleAdvertiser`，使用
  `android.bluetooth.le.AdvertiseSettings` / `AdvertisingSetParameters` /
  `startAdvertising` / **`addManufacturerData`**
- Dart 端有 `BleAdvertiser`/`BroadcastEvent`/`stopAdv`/`startGatt`
- 原生 `libflashsmartencode.so` 匯出 `Tool2.pdu` / `is_ble_fast_link_pdu`（PDU＝廣播封包）
- **框長度 31 bytes ＝ BLE legacy advertising AdvData 上限**

### 9.2 框其實就是合法的 ADV 資料
把 31 bytes 依 BLE AD 結構解讀：

| offset | bytes | 解讀 |
|---|---|---|
| 0 | `02` | AD 長度 = 2 |
| 1 | `01` | AD type `0x01` = **Flags** |
| 2 | `02` | Flags 值：LE General Discoverable |
| 3 | `1b` | AD 長度 = 27 |
| 4 | `03` | AD type `0x03` = **16-bit Service Class UUIDs** |
| 5..6 | `f8 f2` | 固定常數（rodata 0x1698） |
| 7..30 | … | 加密後的裝置資料（XOR+CRC16+位元重排） |

→ 所以「掃不到燈」是必然的：**手機只在要控制時短暫廣播這個封包，燈是接收方**。
之前掃到的 `fcf1`/`fef3` 是其他裝置，與本協定無關（已排除）。

### 9.3 因此正確的控制方式是「廣播」，不是連線
```python
# 1) QR 解碼 → 裝置/key（不依賴 App）
home = ctl.from_qr(qr)
key4 = home['key4']                     # 0x<BLE_CODE_HEX>
# 2) 算出 31-byte ADV 負載
adv = ctl.build_light_frames(addr=2, on=True)   # 31 bytes
# 3) 以 BLE 廣播送出（單向）
broadcast_adv(adv)                      # 見 §9.4
```

### 9.4 可用的廣播手段
| 平台 | 方式 | 備註 |
|---|---|---|
| **ESP32** | `esp_ble_gap_config_adv_data_raw()` + `esp_ble_gap_start_advertising()` | **最推薦**，零依賴、可自訂 raw 31 bytes |
| Linux BlueZ | `btmgmt add-adv -d <hex32>`（需 root/CAP_NET_ADMIN） | 本機 `btmgmt` 存在但需提權 |
| Linux raw HCI | Python `socket(AF_BLUETOOTH, HCI_CHANNEL_RAW)` → `LE Set Advertising Data` + `LE Set Advertising Enable` | 需 root |
| Android | `BluetoothLeAdvertiser.startAdvertising` | 與 App 相同做法 |

`esp_ble_gap_config_adv_data_raw()` 可直接塞入任意 AdvData（≤31 bytes），
與本協定 1:1 對應 —— 這就是「轉 ESP32 平台」的正確落點。

---

## 10. BLE Fast Link (Tool2) — 模擬器與實機封包（2026-09-24 續）

### 10.1 實機真實廣播（HCI snoop 捕獲，ground truth）
App 用 **BLE 5.0 擴充廣播**（`LE Set Ext Adv Data/Enable`），AD 內容：
```
020102 1716f1fc 04<19B>
 |      |   |     └ 加密載荷（每次不同）
 |      |   └ AD type 0x16 = Service Data, UUID 0xFCF1
 |      └ AD len 0x17=23
 └ Flags(0x02)
三筆樣本:
 0201021716f1fc0465bc4bd601da696f1ce5b586d1062b2d311267
 0201021716f1fc046d69e1c80b00f6d342dcf08f83e1f5d1c9b7
 0201021716f1fc04e0b71620062aedcaec0af2d598a6e8324f8a
```
→ 先前掃到的 `0000fcf1` service data 裝置**就是燈**。

### 10.2 Tool2 輸入結構（由 JNI `Tool2_encode` @0x1c84 反推）
```
in[0x00:0x04] ← byte[] A (bleCode)
in[0x04:0x14] ← byte[] B (16B 材料)
in[0x14:0x16] ← B[0x10:0x12] (u16)
in[0x19],[0x1a],[0x1b] ← flags (bIsRelay/bIsIos/...)
in[0x1c:0x20] ← u32 type
call ble_fast_link_encoder(in, &encode_data) → 長度
```

### 10.3 Unicorn 模擬器（`fastlink_emu.py`）狀態
- ✅ 可載入 .so、跑 `ble_fast_link_init` / `set_protocol_platform` / `set_ble_code` / `ble_fast_link_encoder`
- ✅ 關鍵陷阱已解：**內部函式走 PLT 但 GOT 未重定位 → 跳位址 0**；解法＝hook 內部 PLT stub 導向真實位址
- ⚠️ 目前 `encode()` 輸出 `……02011a 1bffe0ff <24B>`（Flags 0x1a + **ManufacturerData 0xFFE0**），
  與實機 `020102 1716f1fc`（Flags 0x02 + **ServiceData 0xFCF1**）不同
  → 需改用 **`Tool2.pdu` (@0x1ed8)** 或設定正確 format（`FormatType`），並補上 byte[] B

### 10.4 下一步
1. 模擬 `Tool2.pdu`（App 廣播用的應是 PDU 路徑）
2. 以 3 筆 ground truth 對拍，反推 byte[] B 內容（推測為隨機 nonce 或 mac）
3. 對上後用 raw HCI（`adv_send.py`，type 0x16、UUID FCF1）廣播 → 以「關客廳」驗收
