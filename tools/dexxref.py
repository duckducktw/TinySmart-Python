#!/usr/bin/env python3
import sys, logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

mode = sys.argv[1] if len(sys.argv) > 1 else 'xref'
path = 'analysis/apk/classes.dex'
dex = DEX(open(path, 'rb').read())
dx = Analysis(dex)

if mode == 'xref':
    for m in dx.find_methods(classname='Lcom/jingyuan/encodelib/.*'):
        tgt = f"{m.class_name}->{m.name}{m.descriptor}"
        print(f"\n== {tgt}")
        for (c, mm, off) in m.get_xref_from():
            print(f"    from {c.get_name()}->{mm.get_name()}{mm.get_descriptor()} @0x{off:x}")
elif mode == 'classes':
    pats = sys.argv[2].split(',')
    for c in dex.get_classes():
        n = c.get_name()
        if any(p.lower() in n.lower() for p in pats):
            print(n)
