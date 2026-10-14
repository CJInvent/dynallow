#!/bin/bash
# Runs the whole suite. Needs: php 8.1+ (cli, sqlite, openssl, sodium), python3,
# PowerShell 7 (pwsh) on PATH or $PWSH, Docker with the php:8.3-cli-alpine image,
# openssl, fuser. Uses ports 8088, 8099, 2525. Work files go to $IPF_TEST_WORK.
set -e
export IPF_TEST_WORK=${IPF_TEST_WORK:-/tmp/ipf-test}
export IPF_PKG=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p $IPF_TEST_WORK/t
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo 172.17.0.1); echo $GW > $IPF_TEST_WORK/t/gw
"$(dirname "$0")/up.sh"
cd $IPF_TEST_WORK/t
python3 -I ui_test.py $IPF_TEST_WORK/t
python3 -I e2e_test.py $IPF_TEST_WORK/t
