#!/usr/bin/env python3
"""Regenerate src-tauri/data/oui.tsv from Wireshark's manuf database.

Output lines are `<hex prefix>\t<vendor>`, where the prefix is 6, 7 or 9 hex
digits for /24, /28 and /36 assignments respectively.
"""

import pathlib
import re
import subprocess

URL = "https://www.wireshark.org/download/automated/data/manuf"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src-tauri" / "data" / "oui.tsv"

SUFFIX = re.compile(
    r"[\s,]+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|"
    r"ag|sa|s\.a|sas|srl|bv|b\.v|oy|ab|as|a/s|aps|kg|pte|plc|pty|spa|s\.p\.a|"
    r"kk|k\.k|nv|sdn\s+bhd|co\.,?\s*ltd|trading)\.?$",
    re.I,
)


def clean(name):
    name = re.sub(r"\s*\([^)]*\)", "", name).strip(" ,.")
    prev = None
    while prev != name:
        prev = name
        name = SUFFIX.sub("", name).strip(" ,.")
    return name or prev


def main():
    # curl rather than urllib: python.org builds on macOS often lack CA certs.
    text = subprocess.run(["curl", "-sfL", URL], check=True, capture_output=True).stdout.decode("utf-8", "replace")
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) < 2:
            continue
        prefix, bits = (cols[0].split("/") + ["24"])[:2]
        digits = int(bits) // 4
        hexp = prefix.replace(":", "").replace("-", "").upper()[:digits]
        if len(hexp) != digits or digits not in (6, 7, 9):
            continue
        rows.append(f"{hexp}\t{clean(cols[2] if len(cols) > 2 and cols[2] else cols[1])}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} entries to {OUT}")


if __name__ == "__main__":
    main()
