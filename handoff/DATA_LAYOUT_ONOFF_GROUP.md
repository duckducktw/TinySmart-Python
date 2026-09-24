# TinySmart BLE — onMethodCall handler `data` 佈局（單燈／群組 開關·控制）

方法：`com/example/ble_lib/ble_lib/BleLibPlugin;->onMethodCall`（dex 線性 dump = `/tmp/omc.txt`）。
輔助工具：`tools/dumpcases.py`（解析 packed-switch payload → 還原每個 case 的 handler pc）。

## 方法名 → case 編號 的確認方式

1. `onMethodCall` 開頭是 234 個 `const-string v7,"<name>"` → `String.equals` → 命中則
   `const/16 v18, <N>`；最後 `packed-switch v18`（omc.txt line 1890）。
2. 我直接解析該 packed-switch 的 **payload**（code_item raw offset 62660，`ident=0x0100`,
   `size=234`, `first_key=0`），以 `switch_pc=3748 code units` 為基準計算每個 case 的
   handler pc，再對回 androguard basic block，取得 handler 起始位址（下表「handler@」）。
   → 不是用猜的，是 payload 第 N 個 target offset。
3. 交叉驗證：case 153 handler 讀的 key 全是 group*（groupID/productType），語意吻合。

## 常數與 reg↔arg-key 對照（switch 前快取的 const-string）

| reg | 值 |
|---|---|
| v4  | 0 (陣列 index 0) |
| v17 | 1 |
| v10 | 2 |
| v16 | 3 |
| v8  | 4 |
| v5  | arg key `"ctrl"` |
| v7  | arg key `"groupID"` |
| v14 | arg key `"devAddr"` |
| v11 | arg key `"destAddr"` |
| v12 | arg key `"para"` |
| v13 | arg key `"srcAddr"` |

---

## 1) groupControl — case **153** (handler@26264)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **LIGHTCONTROLS**
- 讀取順序：`srcAddr`(v13) → `productType`(byte[]) → `groupID`(v7) → `isOpen`(bool)
  → `brightness` → `yLight` → `wLight` → `red` → `green` → `blue`
- `data` = 12 bytes，依參數走三支（同一 0x03 group cmd）：
  - **純群組開/關**：`[0]=0x43, [1]=productType[1], [2]=productType[0], [3]=arg("groupID"), [4]=(isOpen ? arg("brightness") : 0), [5..11]=0`
  - **CCT（白光/黃光）**：`[0]=0x93, [1]=pt[1], [2]=pt[0], [3]=arg("groupID"), [4]=isOpen?brightness:0, [5..7]=0, [8]=arg("wLight"), [9]=arg("yLight"), [10..11]=0`
  - **RGB**：`[0]=0x93, [1]=pt[1], [2]=pt[0], [3]=arg("groupID"), [4]=isOpen?brightness:0, [5]=arg("blue"), [6]=arg("red"), [7]=arg("green"), [8..11]=0`
- 欄位：`srcAddr = arg("srcAddr")`；**`address` 未設定**（沿用舊值 → 影響 head[0]）；**`member` 未設**；manufacturerIds 未設。

## 2) subGroupCtrl — case **154** (handler@25536)

- `broadcastEvent` = **LIGHTCONTROLS**；`bleEncodeType` = **TYPE2**（CCT/RGB 支）或 **TYPE1**（純開關支）
- 讀取順序：`srcAddr`(v13) → `para`(v12) → `red` → `green` → `blue` → `wLight` → `yLight`
  → `productType`(byte[]) → `subGroupId`(byte[])
- `address` 明確設為 **0**。
- `data`：
  - **CCT（TYPE2, 18B）**：`[0]=0x00, [1]=0xA1, [2]=0xB3, [3]=pt[1], [4]=pt[0], [5]=subGroupId[0], [6]=subGroupId[1], [7]=subGroupId[2], [8]=arg("para"), [9..11]=0, [12]=arg("yLight"), [13]=arg("wLight"), [14..17]=0`
  - **RGB（TYPE2, 18B）**：`[0]=0x00, [1]=0xA1, [2]=0xB3, [3]=pt[1], [4]=pt[0], [5..7]=subGroupId[0..2], [8]=arg("para"), [9]=arg("blue"), [10]=arg("red"), [11]=arg("green"), [12..17]=0`
  - **純開關（TYPE1, 12B）**：`[0]=0x00, [1]=0xA1, [2]=0x63, [3]=pt[1], [4]=pt[0], [5..7]=subGroupId[0..2], [8]=arg("para"), [9..11]=0`
- 欄位：`srcAddr = arg("srcAddr")`；`address = 0`；**`member` 未設**。

## 3) setSwitchControllerOnOff — case **146** (handler@28152)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **LIGHTCONTROLS**
- 讀取順序：`ctrl`(v5) → `para`(v12) → `destAddr`(v11)
- `data` (12B)：`[0]=0x32, [1]=lowAddress(address), [2]=arg("ctrl"), [3]=arg("para"), [4..11]=0`
- 欄位：`address = arg("destAddr")`；無 `srcAddr`/`member`。

## 4) setLightMode — case **3** (handler@59944)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **LIGHTCONTROLS**
- 讀取順序：`devAddr`(v14) → `para`(v12) → `modeId`
- `data` (12B)：`[0]=0x32, [1]=lowAddress(address), [2]=arg("modeId"), [3]=arg("para"), [4..11]=0`
- 欄位：`address = arg("devAddr")`；無 `srcAddr`/`member`。

## 5) setLightModeGroup — case **135** (handler@30288)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **LIGHTCONTROLS**
- 讀取順序：`productType`(byte[]) → `groupId` → `para`(v12) → `modeId`
- `data` (12B)：`[0]=0x53, [1]=pt[1], [2]=pt[0], [3]=arg("groupId"), [4]=arg("modeId"), [5]=arg("para"), [6..11]=0`
- 欄位：**none**（無 `address`/`srcAddr`/`member`）。← 群組命令靠 groupId 定址，head 仍沿用舊 address。

---

## 其他「明顯是 開/關」的方法

## 6) setSwitchControllerOnOffGroup — case **139** (handler@29418)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **LIGHTCONTROLS**
- 讀取順序：`productType`(byte[]) → `groupId` → `ctrl`(v5) → `para`(v12)
- `data` (12B)：`[0]=0x53, [1]=pt[1], [2]=pt[0], [3]=arg("groupId"), [4]=arg("ctrl"), [5]=arg("para"), [6..11]=0`
- 欄位：none。

## 7) tsOn — case **107** (handler@37372) ／ 8) tsOff — case **114** (handler@35782)

- `bleEncodeType` = **TYPE1**；`broadcastEvent` = **TSBLECOMMON** ← 走 **TinySmart 路徑**
- 讀取：`dmac`(hex string) → `hexStringToByteArray` → `bleCode` + `seq`
- 無 `data` 陣列：改呼叫
  `TinySmartTool.controlOn(bleCode, dmacBytes, seq)` / `controlOff(...)`
  → 存進 `bleTinySmartEncodeBean`。
- 欄位：無 `address`/`member`。

## 9) tsColorTemp — case **150** (handler@27428)

- TYPE1 / **TSBLECOMMON**（TinySmart 路徑）
- 讀取：`para`(hex string) → `dmac`(hex string) → `bleCode` + `seq`
- 呼叫 `TinySmartTool.controlColorTemp(bleCode, dmacBytes, seq, paraBytes)`。

> ⚠️ `TinySmartTool.controlOn/controlOff/controlColorTemp/controlBrightness/...` 全部是
> **`public static native`**（smali 無 body）→ 其 data 佈局在 `lib*tinysmartencode.so` 內，
> 無法從 smali 直接取得（需逆向 .so）。

## 10) 參考：設定 `member` 的地方

全 `onMethodCall` 中只有一處 `iput ->member I`（omc.txt:13506），屬於 **`setBleCode`**
handler：讀 `bleCode`(byte[])、`member`(int)，然後 `Tool2.setBleCode(bleCode)`。
→ **所有控制命令都不設 member**。

---

## 結論（路徑）

`groupControl / subGroupCtrl / setSwitchControllerOnOff / setSwitchControllerOnOffGroup /
setLightMode / setLightModeGroup` 全部是 `BroadcastEvent.LIGHTCONTROLS`，**走 `Tool2.encode`
（LIGHTCONTROLS 路徑，getHead→Tool2.encode→interceptByteArry(15,…)→manufacturerId 廣播）**；
只有 `tsOn / tsOff / tsColorTemp`（fans 系列的 `ts*`）走 **TinySmart 路徑**
（`BroadcastEvent.TSBLECOMMON` → native `TinySmartTool.*` → `getAdvertiseData2()` → ServiceUUID）。
