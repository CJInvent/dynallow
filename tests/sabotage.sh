#!/bin/bash
# Usage: sabotage.sh "<description>" "<expected FAIL text>" <file-in-srv> <python-replace-old> <python-replace-new>
S=${IPF_TEST_WORK:-/tmp/ipf-test}
$S/t/up.sh >/dev/null
python3 - "$S/srv/$3" "$4" "$5" <<'PY'
import sys; p,o,n=sys.argv[1:4]; s=open(p).read()
assert o in s, "sabotage anchor not found: " + o
open(p,'w').write(s.replace(o,n,1))
PY
cd $S/t && python3 -I ui_test.py $S/t >/dev/null 2>&1
out=$(STOP_AFTER=attacks timeout 300 python3 -I e2e_test.py $S/t 2>&1)
if echo "$out" | grep -q "FAIL $2"; then echo "CAUGHT   - $1"; else echo "MISSED!! - $1"; echo "$out" | grep -E "PASS|FAIL" | tail -8; fi
