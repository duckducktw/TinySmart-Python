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

TARGETS = {3:"setLightMode",135:"setLightModeGroup",146:"setSwitchControllerOnOff",
 153:"groupControl",154:"subGroupCtrl",107:"tsOn",114:"tsOff",150:"tsColorTemp",145:"settingScene",
 # extra candidates: single light / group on-off
 104:"magicGradientMode",156:"?",157:"?",158:"?",159:"?"}

for c in dex.get_classes():
    if "ble_lib/BleLibPlugin" not in c.get_name(): continue
    for m in c.get_methods():
        if m.get_name() != "onMethodCall": continue
        code=m.get_code(); raw=code.get_raw()
        pos=62660
        ident,size,first=struct.unpack_from("<HH I",raw,pos)
        rels=struct.unpack_from("<%di"%size, raw, pos+8)
        switch_pc_units=(pos-16)//2 - 27574
        ma=dx.get_method(m)
        # build ordered instruction list by pc
        allins=[]
        for b in ma.get_basic_blocks():
            pc=b.get_start()
            for i in b.get_instructions():
                allins.append((pc,i)); pc+=i.get_length()
        allins.sort(key=lambda x:x[0])
        idx={pc:k for k,(pc,_) in enumerate(allins)}
        def dump(start_bytes, maxtag):
            # find nearest ins at or after start
            k=idx.get(start_bytes)
            if k is None:
                # find first >= 
                ks=[kk for kk,(pc,_) in enumerate(allins) if pc>=start_bytes]
                if not ks: return
                k=ks[0]
            out=[]
            for j in range(k, min(k+400, len(allins))):
                pc,i=allins[j]
                out.append(f"  {i.get_name():<22} {i.get_output()}")
                if "startAdv" in i.get_output() and "invoke" in i.get_name():
                    break
            return out
        for case,name in sorted(TARGETS.items()):
            if case>=size: 
                print(f"--- case {case} ({name}) OUT OF RANGE"); continue
            hpc=(switch_pc_units+rels[case])*2
            print(f"\n===== case {case} = {name}  handler@{hpc}")
            o=dump(hpc,None)
            if o:
                print("\n".join(o))
        break
