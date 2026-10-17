#!/usr/bin/env python3
"""Extract control IDs, titles and profile levels from a licensed CIS benchmark PDF.

    python3 tools/extract_benchmark.py CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v3.0.0.pdf 9 v3.0.0

Writes tools/benchmarks/rhel<N>.json. Only metadata is stored - never commit the PDF itself.
Requires poppler-utils (pdftotext).
"""
import json
import os
import re
import subprocess
import sys


def main(pdf, rhel, version):
    text = subprocess.run(["pdftotext", pdf, "-"], check=True, capture_output=True, text=True).stdout
    recs = {}
    for page in text.split("\f"):
        page = page.lstrip()
        if "......." in page[:3000]:          # table of contents
            continue
        m = re.match(r"^(\d+(?:\.\d+)+)\s+(.+?)\s*\((Automated|Manual)\)", page, re.S)
        if not m or "Profile Applicability" not in page:
            continue
        rid = m.group(1)
        if rid in recs:
            continue
        prof = re.search(r"Profile Applicability:(.*?)Description:", page, re.S)
        prof = " ".join(prof.group(1).split()) if prof else ""

        def level(kind):
            lm = re.search(r"Level (\d) - " + kind, prof)
            return int(lm.group(1)) if lm else None
        recs[rid] = {"id": rid, "title": " ".join(m.group(2).split()), "type": m.group(3).lower(),
                     "server": level("Server"), "workstation": level("Workstation")}
    rules = sorted(recs.values(), key=lambda r: [int(x) for x in r["id"].split(".")])
    out = {"benchmark": f"CIS Red Hat Enterprise Linux {rhel} Benchmark", "version": version,
           "rhel": int(rhel), "rules": rules}
    dest = os.path.join(os.path.dirname(__file__), "benchmarks", f"rhel{rhel}.json")
    with open(dest, "w") as f:
        json.dump(out, f, indent=1)
    print(f"{len(rules)} controls -> {dest}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
