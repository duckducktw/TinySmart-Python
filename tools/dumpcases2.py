#!/usr/bin/env python3
import sys, logging, struct
logging.disable(logging.CRITICAL)
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis
path='analysis/apk/classes.dex'
dex=DEX(open(path,'rb').read()); dx=Analysis(dex)
TARGETS={139:"setSwitchControllerOnOffGroup",116:"setSwitchType",106:"open",105:"isOn",
         157:"?",158:"?",104:"magicGradientMode",131:"setCtLightBrightness",123:"WPLsetBrightness"}
for c in dex.get_classes():
    if "ble_lib/BleLibPlugin" not in c.get_name(): continue
    for m in c.get_methods():
        if m.get_name()!="onMethodCall": continue
        code=m.get_code(); raw=code.get_raw()
        pos=62660; ident,size,first=struct.unpack_from("<HH I",raw,pos)
        rels=struct.unpack_from("<%di"%size,raw,pos+8)
        sw_units=(pos-16)//2-27574
        ma=dx.get_method(m)
        allins=[]
        for b in ma.get_basic_blocks():
            pc=b.get_start()
            for i in b.get_instructions(): allins.append((pc,i)); pc+=i.get_length()
        allins.sort(key=lambda x:x[0]); idx={pc:k for k,(pc,_) in enumerate(allins)}
        for case,name in sorted(TARGETS.items()):
            if case>=size: continue
            hpc=(sw_units+rels[case])*2
            k=idx.get(hpc)
            if k is None:
                ks=[kk for kk,(pc,_) in enumerate(allins) if pc>=hpc]
                k=ks[0] if ks else None
            if k is None: continue
            print(f"\n===== case {case} = {name}  handler@{hpc}")
            for j in range(k,min(k+200,len(allins))):
                pc,i=allins[j]
                print(f"  {i.get_name():<22} {i.get_output()}")
                if "startAdv" in i.get_output() and "invoke" in i.get_name(): break
        break
