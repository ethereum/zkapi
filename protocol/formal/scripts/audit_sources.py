#!/usr/bin/env python3
"""Fail if any Lean source of protocol/formal uses an escape hatch.

    python3 -I protocol/formal/scripts/audit_sources.py

Covers ZkapiFormal/ and the proof of concept in poc/ZkapiPoC/. Comments and string literals are
stripped first; then every source must be free of `sorry`,
`admit`, `native_decide`, `axiom` declarations, `unsafe`, `implemented_by`, `extern`, `opaque`
and `debug.skipKernelTC`. This complements ZkapiFormal/Audit/Axioms.lean, which checks the axioms
the kernel actually records for every declaration under `Zkapi`.
"""

import re
import sys
from pathlib import Path

FORMAL = Path(__file__).resolve().parent.parent
FORBIDDEN = ["sorry", "admit", "native_decide", "axiom", "unsafe", "implemented_by", "extern",
             "opaque", "skipKernelTC", "ofReduceBool"]


def strip(src):
    out, i, depth = [], 0, 0
    while i < len(src):
        if src.startswith("/-", i):
            depth += 1
            i += 2
        elif depth and src.startswith("-/", i):
            depth -= 1
            i += 2
        elif depth:
            i += 1
        elif src.startswith("--", i):
            j = src.find("\n", i)
            i = len(src) if j < 0 else j
        elif src[i] == '"':
            j = i + 1
            while j < len(src) and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append('""')
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def main():
    bad = []
    files = (sorted((FORMAL / "ZkapiFormal").rglob("*.lean")) + [FORMAL / "ZkapiFormal.lean"] +
             sorted((FORMAL / "poc" / "ZkapiPoC").rglob("*.lean")) + [FORMAL / "poc" / "ZkapiPoC.lean"])
    for path in files:
        code = strip(path.read_text())
        for word in FORBIDDEN:
            for m in re.finditer(r"(?<![\w.'])" + re.escape(word) + r"(?![\w'])", code):
                line = code.count("\n", 0, m.start()) + 1
                bad.append("%s:%d: %s" % (path.relative_to(FORMAL), line, word))
    if bad:
        print("\n".join(bad))
        sys.exit(1)
    print("ok: %d Lean files, no escape hatches" % len(files))


if __name__ == "__main__":
    main()
