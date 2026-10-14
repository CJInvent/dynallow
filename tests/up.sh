#!/bin/bash
# (Re)start mocks + a fresh server. PID files, never pkill -f.
S=${IPF_TEST_WORK:-/tmp/ipf-test}; TESTS=$(cd "$(dirname "$0")" && pwd); mkdir -p $S/t; cp $TESTS/*.py $TESTS/*.sh $S/t/
for f in $S/t/*.pid; do [ -f "$f" ] && kill $(cat $f) 2>/dev/null; rm -f "$f"; done
fuser -k 8088/tcp 8099/tcp 2525/tcp >/dev/null 2>&1; sleep 0.5
python3 -I $S/t/mock.py 8099 2525 > $S/t/mock.log 2>&1 & echo $! > $S/t/mock.pid
$S/t/setup_srv.sh $S/srv > $S/t/init.log 2>&1 || { cat $S/t/init.log; exit 1; }
(cd $S/srv && php -S 0.0.0.0:8088 -t $S/srv/public $S/srv/public/_router.php > $S/t/srv.log 2>&1 & echo $! > $S/t/srv.pid)
sleep 0.8
