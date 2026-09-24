# TinySmart 廣播控制 — App 邏輯鏈完整還原（2026-09-24）

> 目標：不靠擷取，用 Python 從 QR/家庭模型直接產生 31-byte ADV 封包並廣播。
> 本檔記錄**已還原的完整調用鏈**與常數，作為 Python 重實作的規格。

---

## 0. 一句話結論

App（`com.iot.tinysmart` v2.4.5，Flutter）按下開關時的完整鏈路**已 100% 打通**：

```
UI 卡片
  → BleUtils.<cmd>()            [package:easysmart01/logic/untils/ble.dart]
  → BleLib.<cmd>()              [package:ble_lib/ble_lib.dart]
  → MethodChannel('ble_lib').invokeMethod(<cmd>, argsMap)
  → BleLibPlugin.onMethodCall() [Java: com.example.ble_lib.ble_lib]
      ├ 設定 this.bleEncodeType / this.broadcastEvent / this.address / this.member / this.data
      └ startAdv()
          ├ getHead(this.seq)  → 4-byte head
          ├ 依 broadcastEvent 分支：
          │   • LIGHTCONTROLS → Tool2.encode(head, data, 0,0,0, encodeType)
          │        → interceptByteArry(15, len, encode)   (丟前 15 bytes)
          │        → AdvertiseData.Builder().addManufacturerData(manufacturerIds, bytes)  → 0xFFE0
          │   • TSBLECOMMON   → TinySmartTool → interceptByteArry(5, len) → getAdvertiseData2() → ServiceUUID(0xFCF1/F3FE)
          └ SmartDeviceManager.startAdvertising(advertiseData, cb)   (Ext Adv)
```

實機擷取（btsnoop）驗證：`02 01 02 | 1b ff e0 ff | <24B>` = 31 bytes，完全吻合。

---

## 1. Java 端：`com.jingyuan.encodelib`

| 類別/方法 | 說明 |
|---|---|
| `Tool2.init(int, int, byte[] bleCode, byte[] pairBleCode)` | 初始化（兩個 int = FormatType/InitFormatType）|
| `Tool2.setBleCode(byte[])` / `setPairBleCode(byte[])` | 設金鑰（QR 解出的 `home.bleCode` = `0x<BLE_CODE_HEX>`）|
| `Tool2.encode(byte[] head, byte[] data, bool bIsRelay, bool bIsIos, bool bIsEnc, int formatType) → BleFastEncodeBean` | 產生 `encode` 陣列 |
| `Tool2.decode(byte[])` | 反向 |
| `BleFastEncodeBean` | `successFlag:int`, `encode:byte[]` |

原生符號（`libflashsmartencode.so`）：
`Java_com_jingyuan_encodelib_Tool2_init@0x25bc`, `_pdu@0x1ed8`, `_encode@0x1c84`, `_decode@0x1fac`,
`_setBleCode@0x1bcc`, `_setPairBleCode@0x1c28`, `ble_fast_link_encoder@0x28a0`
→ 只匯入 `rand`（無 `srand`/`time`）⇒ nonce 來自預設 PRNG。

`encode()` 輸出結構（40 bytes 實測）：
```
[0:8]  常數前綴 (模擬器: 42 25 66 55 44 33 22 11)
[8:11] Flags AD        (模擬器 02 01 1a；被 plugin 丟棄)
[11:15] 1b ff e0 ff    (被 plugin 丟棄)
[15:39] 24-byte 加密載荷  ← 這裡才是真正上空的 ManufacturerData
[39]   0 padding
```
⇒ plugin `interceptByteArry(15, len, encode)` = `encode[15:15+len]` = 24 bytes。

## 2. Java 端：`com.example.ble_lib.ble_lib`

### 2.1 `BleLibPlugin.getHead(int seq) → byte[4]`
以 `this.broadcastEvent` 分支（`BroadcastEvent` ordinal → case 由 `BleLibPlugin$3` 決定）：

| BroadcastEvent | ordinal | case | head 內容 |
|---|---|---|---|
| PAIR | 0 | 1 | `[0xF0, seq, 0, 0]` |
| SENDADDRESS | 1 | 2 | `[0x80, seq, 0xFF, 0]` |
| **LIGHTCONTROLS** | **2** | **3** | **`[(getHighAddress(address)+209)&0xFF, seq, member, 0]`** |
| EDITROOM | 3 | 4 | `[(getHighAddress(address)+80)&0xFF, seq, member, 0]` |
| CREATEFINISH | 4 | 5 | `[(getHighAddress(address)+208)&0xFF, seq, member, 0]` |
| OPENPAIRWINDOW | 5 | 6 | `[(getHighAddress(address)+32)&0xFF, seq, v1, 0]` |
| PRODUCTTEST | 6 | 7 | `[0x00, seq, v1, 0]` |
| TSPAIR / TSSENDADDRESS / TSBLECOMMON | 7/8/9 | 8/9/10 | （走 TinySmart 路徑）|

- `getHighAddress(a) = (a >> 8) & 0x0F`
- `getLowAddress(a)  = a & 0xFF`
- `seq` 來自 `BleLibPlugin$PacketSequenceGenerator.getNextSequence()`（在 handler 內取一次，`startAdv()` 再讀 `this.seq` 進 head[1]）
- ⇒ **同一命令重送 4 次時，只有 seq 遞增；但因加密有擴散，整個 24B body 每次都不同。**

### 2.2 `startAdv()`
```
if (bluetoothLeAdvertiser==null || advertiseCallback==null || settings==null) initBleController();
getHead(this.seq);
smartDeviceManager.startAdvertising(this.advertiseData, cb);
```

### 2.3 廣播參數（實機 HCI 對照，handle 3/6/7/8/9 各一組）
`LE Set Ext Adv Params`：
```
handle=3..9, event_properties=0x0013 (legacy PDU + connectable + scannable),
primary_interval_min=160(0xA0), max=210(0xD2), channel_map=0x07,
own_addr_type=0x01 (random), peer_addr_type=0, peer_addr=000000000000,
filter_policy=0, tx_power=0x01, primary_phy=0x01(1M),
secondary_max_skip=0x00, secondary_phy=0x01, SID=handle, scan_req_notif=0
```
`LE Set Adv Set Random Address` → 隨機 6 bytes；`Set Ext Adv Data` op=0x03 frag=0x01 len=0x1f；
`Set Ext Adv Enable` enable=1, num_sets=1, [handle, dur=0, max_events=0]。
送法：**5 個 adv set 同時 carry 同一 frame，每 ~1s 一輪，共 4 輪**（每輪前先 disable 全部）。

### 2.4 MethodCall 常用的 argument key
`"ctrl"`, `"groupID"`, `"devAddr"`, `"destAddr"`, `"para"`, `"srcAddr"`, `"lum"`, `"speed"`, `"len"`, `"step"`, `"hue"`, `"brightness"` …
（每個 handler 自 `data` 陣列，例如某 handler：`data[0]=0; data[k]=0xC9; …`）

## 3. Dart 端

- `BleUtils`（`easysmart01/logic/untils/ble.dart`）198 個方法：`tsOn/tsOff/groupControl/subGroupCtrl/tsColorTemp/tsRgbChange/setLightModeGroup/settingScene/…`
- `BleLib`（`ble_lib/ble_lib.dart`）91 個方法，與 MethodChannel method name 一對一。
- method 名稱 → onMethodCall 內 case 編號（例：`groupControl`=153、`subGroupCtrl`=154、`setSwitchControllerOnOff`=146、`settingScene`=145）。

## 4. 已完成的工具

| 工具 | 用途 |
|---|---|
| `tools/fl_probe.py` | Tool2 編碼器探針（可變 rand/B/type/flags/plat）|
| `tools/fl_dump.py` | dump 編碼器記憶體（找明文/keystream）|
| `tools/ts_dump.py` | btsnoop 解析（帶時間戳，濾 adv 指令）|
| `tools/replay_adv.py` / `replay_adv2.py` | HCI 原始廣播重播（v2 = 忠實 5-handle 複製）|
| `tools/dexlist.py` / `dexxref.py` / `dexsmali.py` | androguard 反編譯（列類別/交叉引用/smali）|

## 5. 尚未還原（下一步）

1. **各命令的 `data` 內容**：逐個讀 `onMethodCall` 的 packed-switch handler，
   取出對「單燈開/關、亮度、色溫、房間群組」的 `data` byte 佈局 + 用到的 arg key。
2. **`Tool2.init` 的兩個 int 參數** 與 `manufacturerIds` 值（應為 0xFFE0）之確認。
3. **加密 nonce 來源**：`.so` 內 `rand()` 序列 vs `seq`——用模擬器對拍實機 body 反推。
4. **Python 重實作**：`QR → 家庭模型 → head+data → encode(可用模擬器或純 py) → 31B ADV → HCI 廣播`。
5. **TX 自我驗證**：手機掃 BLE 確認廣播真的送出（先前重播未被燈回應，需排除 TX / nonce / 命令三種可能）。
