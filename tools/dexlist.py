#!/usr/bin/env python3
import sys
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

PAT = sys.argv[2] if len(sys.argv) > 2 else 'encodelib'
path = sys.argv[1]
dex = DEX(open(path, 'rb').read())
dx = Analysis(dex)
print(f"# dex={path} classes={len(list(dex.get_classes()))}")
for c in dex.get_classes():
    n = c.get_name()
    if PAT in n:
        print("\n#### CLASS", n)
        for m in c.get_methods():
            print("   ", m.get_name(), m.get_descriptor())
