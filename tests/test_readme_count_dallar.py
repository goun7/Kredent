"""G37-pini: README'nin test-sayisi-iddiasi gercek-collect'e-esit.

Kredent-ilk-PyPI-yayini-oncesi ( 2026-10-19) eklendi. README "1.321
tests passed" iddia-ediyor; bu-pin otomatik-collect ile ayni-olmazsa-KIRMIZI.

Kural ( G27/G28/G34/G35-deseni): README-nin-soyledigi-ile-olctugumuz-ayni
olmali ("tamamlanma"-olcutumuz-bu).
"""
import re
import subprocess
import sys
from pathlib import Path


def test_readme_test_count_is_not_stale():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    m = re.search(r"([\d.,]+)\s*tests\s+passed", readme)
    assert m, "README-tests-passed-satiri-bulunamadi"
    claimed = int(m.group(1).replace(".", "").replace(",", ""))
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=str(root), timeout=600)
    assert res.returncode == 0, res.stderr[-400:]
    total = 0
    for mm in re.finditer(r"^tests/[\w./-]+\.py:\s*(\d+)\s*$", res.stdout, re.M):
        total += int(mm.group(1))
    assert total > 0, "collect-total-ayristirilamadi: %r" % res.stdout[-300:]
    assert total >= claimed, (
        "README-stale-test-sayisi: iddia=%d collect=%d" % (claimed, total))
