# TinySmart — 完整破解（2026-09-24）✅

## 全鏈路（已驗證）

```
QR "FTDSF|2|<b64>"  --AES-128-CBC(key=1a2c3b16…, iv=ftd95279527a2c3c)--> {shareID, platCode}
   │
   ├─ POST https://flashsmart.icoding.net.cn/flashsmart/queryShareInfo   (body = base64(JSON))
   │     → memberInfo.shareDeviceJson (base64 JSON) = {home, rooms, devices, groups, scenes}
   │     → home.bleCode (base64) = 4B  → bleCode4 = 0x<BLE_CODE_HEX>
   │
   ├─ POST https://ftdauth.jasonghost.com:9527/wechatAuth/ftdAuth/QueryFlashMeshCode  (body = 原始 JSON)
   │     → {"code":0,"data":"3273EB871F7E2EF7A4420B421F625168"} = 16B AES key (meshKey)
   │
   ├─ ble_fast_link_init(0, 86, bleCode4, meshKey)  ; ble_fast_link_set_protocol_platform(2)
   │
   ├─ encode(head4, data16)  → 40B  → 取 [15:39] = body24
   │
   └─ ADV = 02 01 02 | 1b ff e0 ff | body24   (31B, legacy ext adv, 5 個 adv set 同送)
```

## head / data 格式（由實機 frame 解出）

- `head = [ (addr>>8 & 0x0F) + 208 , seq , 3 , 0 ]`  ← 實機皆為 `d0 <seq> 03 <chk>`
  - `chk`（head[3]）由 encode 產生（檢查碼），輸入填 0
  - `seq` 每送一發 +1
- `data`（12B）— `groupControl`：
  - 開關 `43 <pt1> <pt0> <groupId> <isOpen?brightness:0> 00 00 00 00 00 00 00`
  - CCT  `93 <pt1> <pt0> <groupId> <brightness> 00 00 00 <wLight> <yLight> 00 00`
- `setSwitchControllerOnOffGroup`：`53 <pt1> <pt0> <groupId> <ctrl> <para> 00…`
- `productType`「2ba8」→ 實機 frame 證實 `pt1=0x2a, pt0=0xa8`

## 實機對拍（8 筆全解）

| 時間 | head | data |
|---|---|---|
| 17:41a | d00103 5f | `432aa801ff00000000000000` |
| 17:41b | d00203 64 | `432aa801ff00000000000000` |
| 17:41c | d00303 b7 | `73c0cb01000080ff00000000` |
| 17:41d | d00403 0e | `73c0cb01000080ff00000000` |
| 17:46a | d00503 22 | `432aa801ff00000000000000` |
| 17:46b | d00603 d4 | `432aa801ff00000000000000` |
| 17:46c | d00703 c9 | `73c0cb01000080ff00000000` |

（同 cmd 重送 → data 相同、僅 seq 遞增）

## 可用工具

- `tinysmart_full.py` — 完整 Python 實作（QR→模型→key→編碼→廣播）
- `tools/fl_encode.py` — encode / ad_payload
- `tools/fl_decode.py` — decode（丟實機 body24 或 28B `1bffe0ff+body`）
- `tools/fl_probe.py` / `fl_dump.py` / `fl_plat.py` — 模擬器探針
- `tools/replay_adv2.py` — 忠實 5-handle 擴充廣播
- `tools/dexsmali.py` / `dexlist.py` / `dexxref.py` / `dumpcases.py` — dex 反編譯
- `tools/ts_dump.py` — 帶時間戳 btsnoop 解析
- `handoff/DATA_LAYOUT_ONOFF_GROUP.md` — 各 method 的 data 佈局

## 關鍵教訓

1. `libflashsmartencode.so` 匯入只有 `rand`（無 srand/time）→ nonce 來自 PRNG；**encoder 確定性**（同輸入同輸出）
2. 要解實機 frame **必須**用 App 自己的 meshKey（`QueryFlashMeshCode`），家庭 bleCode 不是加密金鑰
3. 該 API 吃**原始 JSON** body；分享 API 吃 **base64(JSON)** body
4. `.so` 內部函式走 PLT/GOT 未重定位 → Unicorn 需 hook PLT stub（fastlink_emu.py 已處理）
