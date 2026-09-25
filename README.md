# TinySmart Python

TinySmart / FlashSmart 智能燈具 — **BLE 廣播控制協定的完整 Python 重實作**。
只需要一個 QR Code，就能取得家庭模型、加密金鑰，並自行產生控制封包（房間/燈具 開關、亮度、色溫）。

> ⚠️ 僅供**自有裝置**互通性研究。本專案不含任何原廠二進位檔（`.so` / APK / dex），
> 需自行從你**自己購買的 App** 中提取（見下方「前置需求」）。

---

## 原理（完整鏈路）

```
QR "FTDSF|2|<b64>"
  │  AES-128-CBC 解密 (QR_KEY / QR_IV)
  ▼
shareID ──► 分享 API ──► 家庭模型
                          ├ home.bleCode  → bleCode4 (4B)
                          ├ rooms[].roomId          → groupId
                          └ devices[]: mac / address / type
  │
  ├─► QueryFlashMeshCode API ──► meshKey (16B, AES)
  │
  ├─► ble_fast_link_init(0, 86, bleCode4, meshKey)
  │   ble_fast_link_set_protocol_platform(2)
  │
  ├─► encode(head4, data16) ──► body24
  │
  └─► ADV = 02 01 02 | 1b ff e0 ff | body24   （31B legacy extended advertising）
                 ▲ Flags  ▲ ManufacturerData(0xFFE0)
      同時在 5 個 advertising set（handle 3/6/7/8/9）廣播，共 4 輪
```

### `head`（4 bytes）
```
head = [ (addr>>8 & 0x0F) + 208 , seq , 3 , 0 ]
```
`seq` 每送一發 +1；`head[3]` 由 encoder 產生檢查碼（輸入填 0）。

### `data`（12 bytes，`groupControl`）
| 用途 | 格式 |
|---|---|
| 開關 | `43 <pt1> <pt0> <groupId> <isOpen?brightness:0> 00 00 00 00 00 00 00` |
| 亮度／色溫 | `93 <pt1> <pt0> <groupId> <brightness> 00 00 00 <wLight> <yLight> 00 00` |
| 群組開關 | `53 <pt1> <pt0> <groupId> <ctrl> <para> 00 …` |

> ⚠️ **調亮度一定要用 `0x93`（CCT 指令）**。`0x43` 雖然欄位定義上第 5 byte 也是
> 「isOpen ? brightness : 0」，但**實測在燈已亮的狀態下送 `0x43` + brightness 完全無效**
> （開/關本身有效）。要改亮度請送 `0x93`，並帶上目前的 `wLight` / `yLight`。
> 見 `bright.py`。

「雙色燈」(type `2ba8`) 的 `productType` 實測為 `(pt1, pt0) = (0x2A, 0xA8)`。

---

## 使用

```bash
pip install pycryptodome unicorn pyelftools

# 1) 提取原廠編碼器（從你自己的 App）
#    APK: assets/flutter_assets / lib/arm64-v8a/libflashsmartencode.so
#    放到 fastlink_emu.py 的 SO 路徑（預設 /tmp/tsx/lib/arm64-v8a/libflashsmartencode.so）

# 2) 一鍵：QR → 家庭模型 → 金鑰 → 往返驗證
python3 tinysmart_full.py            # 讀 tools/newqr.txt

# 3) 廣播（需要 root/raw HCI）
sudo python3 tools/replay_adv2.py <AD_HEX_1> <AD_HEX_2> ...

# 4) 開關（省略房間 = 全部）
python3 lights.py on 客廳 主臥
python3 lights.py off

# 5) 亮度 / 色溫（走 0x93 CCT 指令）
python3 bright.py 主臥 255            # 亮度最大，中性色溫 (w=128,y=128)
python3 bright.py 主臥 128 255 0      # 亮度128、最暖
python3 bright.py 主臥 255 0 255      # 亮度最大、最冷
python3 bright.py 主臥 64 --dry       # 只印 payload
python3 bright.py 全屋 200            # 全屋（會自動展開成各房間）

# 6) 廣播節奏微調（預設 seqs=1 rounds=4 gap=1.0）
python3 lights.py off 客廳 --rounds 3 --gap 0.8
```

> `lights.py` / `bright.py` 需在專案根目錄執行，並把 `libflashsmartencode.so`
> 放好（見下方「前置需求」）。廣播需 root，`broadcast()` 會自行 `sudo -A`。
>
> **房間與節奏（實機驗證，2026-09-25）**
> - 房間：全屋 = `1`(客廳5) + `2`(主臥3) + `6`(衛生間1)。API 裡另有一個 `roomId=0`
>   的空殼（底下 0 顆燈），**送 roomId 0 完全沒反應**，`全屋` 會自動展開成 `[1,2,6]`。
> - 節奏：`seqs=1 rounds=4 gap=1.0` 實測有效（單房 ~7s、全屋 ~16s）。
>   實測 `rounds=2 gap=0.3` **無效**——接收端要的是「時間拉開 ~4 秒」，
>   不是短時間內連發。想再快請逐格測 `--rounds 3`；有燈漏掉就加 `--seqs`。

### Python API

```python
from tinysmart_full import (QrCodec, fetch_home, fetch_mesh_key,
                            Codec, head, cmd_group_switch, broadcast)

info = QrCodec.decrypt(open("qr.txt").read().strip())
home = fetch_home(info["shareID"])
codec = Codec(home["key4"].to_bytes(4, "big"), fetch_mesh_key())

# 關客廳（roomId=1）
data = cmd_group_switch(1, on=False)
payloads = [codec.ad(head(seq, addr=0), data) for seq in range(1, 9)]
broadcast(payloads)          # 5-handle × 4 輪
```

---

## 檔案

| 檔案 | 說明 |
|---|---|
| `tinysmart_full.py` | 完整實作（QR / API / 編解碼 / 指令 / 廣播） |
| `lights.py` | CLI：房間 開/關 |
| `bright.py` | CLI：房間 亮度 / 色溫（0x93 CCT） |
| `SOLVED.md` | 完整規格書（含實機封包對拍表） |
| `REVERSED_CHAIN.md` | App 調用鏈逆向紀錄 |
| `RESEARCH.md` | 早期研究紀錄（雲端 API、家庭模型等） |
| `tools/fl_encode.py` `fl_decode.py` | Tool2 編解碼器 |
| `tools/fl_probe.py` `fl_dump.py` `fl_plat.py` | 模擬器探針 |
| `tools/replay_adv2.py` | 忠實 5-handle 擴充廣播 |
| `tools/dexsmali.py` `dexlist.py` `dexxref.py` `dumpcases.py` | dex 反編譯工具 |
| `tools/ts_dump.py` `snoop.py` `adv_dump.py` | btsnoop / HCI log 解析 |
| `handoff/DATA_LAYOUT_ONOFF_GROUP.md` | 各 method 的 `data` 佈局 |

---

## 前置需求

- 原廠 `libflashsmartencode.so`（arm64-v8a）— **從你自己的 APK 提取**，本專案不散布
- Linux 主機 + 藍牙網卡（raw HCI，需 root；以 `HCI_CHANNEL_USER` 送擴充廣播）
- Python: `pycryptodome`, `unicorn`, `pyelftools`

## 已知限制

- `productType` / `head[2]` 為**產品線/協定常數**（非 QR 資料）；異型號需重新對拍
- 目前僅以「雙色燈 (type 2ba8)」實機驗證
- **亮度只能走 `0x93`（CCT）**：`0x43` 的 brightness 欄位在燈已亮時無效（實測 2026-09-24）
- 加密金鑰 `meshKey` 由原廠 auth 端點取得，可能隨 App 版本/服務端變動
