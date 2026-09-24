#!/usr/bin/env python3
import sys, logging, struct
logging.disable(logging.CRITICAL)
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

path = 'analysis/apk/classes.dex'
dex = DEX(open(path, 'rb').read())
dx = Analysis(dex)

TARGET_CASES = {0:"changeRoom",1:"setColorfulLightBrightnessChange",2:"setFanRotationSpeed",
 3:"setLightMode",4:"stopScanning",107:"tsOn",114:"tsOff",135:"setLightModeGroup",
 146:"setSwitchControllerOnOff",145:"settingScene",150:"tsColorTemp",153:"groupControl",154:"subGroupCtrl"}

for c in dex.get_classes():
    if "ble_lib/BleLibPlugin" not in c.get_name(): continue
    for m in c.get_methods():
        if m.get_name() != "onMethodCall": continue
        code=m.get_code()
        raw=code.get_raw()
        # payload
        pos=62660
        ident,size,first=struct.unpack_from("<HH I",raw,pos)
        rels=struct.unpack_from("<%di"%size, raw, pos+8)
        switch_pc_units = (pos-16)//2 - 27574
        print("size",size,"switch_pc_units",switch_pc_units, "-> bytes", switch_pc_units*2)
        ma = dx.get_method(m)
        blocks={}
        for b in ma.get_basic_blocks():
            blocks[b.get_start()]=b
        print("sample block starts:", sorted(blocks)[:8], "max", max(blocks))
        for i in range(size):
            hpc_units = switch_pc_units + rels[i]
            hpc_bytes = hpc_units*2
            if i in TARGET_CASES:
                b = blocks.get(hpc_bytes)
                print(f"case {i:3d} {TARGET_CASES[i]:35s} target_units={hpc_units} bytes={hpc_bytes} block={'FOUND' if b else 'MISS'}")
        break
