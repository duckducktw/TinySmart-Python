#!/usr/bin/env python3
import sys, logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

path = 'analysis/apk/classes.dex'
cls_pat = sys.argv[1]
meth_pat = sys.argv[2] if len(sys.argv) > 2 else None

dex = DEX(open(path, 'rb').read())
dx = Analysis(dex)

for c in dex.get_classes():
    cn = c.get_name()
    if cls_pat not in cn:
        continue
    for m in c.get_methods():
        if meth_pat and meth_pat not in m.get_name():
            continue
        print(f"\n===== {cn}->{m.get_name()}{m.get_descriptor()}")
        try:
            ma = dx.get_method(m)
            for b in ma.get_basic_blocks():
                for ins in b.get_instructions():
                    print(f"  {ins.get_name():<22} {ins.get_output()}")
        except Exception as e:
            print("   <err>", e)
