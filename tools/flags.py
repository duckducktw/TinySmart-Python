#!/usr/bin/env python3
import logging
logging.disable(logging.CRITICAL)
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
path='analysis/apk/classes.dex'
dex=DEX(open(path,'rb').read())
for c in dex.get_classes():
    if "TinySmartTool" not in c.get_name(): continue
    for m in c.get_methods():
        if m.get_name() in ("controlOn","controlOff","controlColorTemp","controlBrightness"):
            print(m.get_name(), m.get_access_flags_string(), m.get_descriptor())
