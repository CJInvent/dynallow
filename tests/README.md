# Tests (for developers)

`./run_all.sh` runs everything against a throw-away server, with mock DNS
providers, a mock SMTP server, the real PowerShell agent and the real Docker
agent in a real container.

Needs: PHP 8.1+ CLI (sqlite3, openssl, sodium), python3, PowerShell 7 (`pwsh`
on PATH or `PWSH=/path/to/pwsh`), Docker with the `php:8.3-cli-alpine` image,
openssl and fuser. Uses ports 8088, 8099, 2525. Work files go to
`$IPF_TEST_WORK` (default `/tmp/ipf-test`).

- `ui_test.py` — the web UI as a browser would use it (login, settings, DNS accounts, survey).
- `e2e_test.py` — installers downloaded from the UI; enrollment; relay/replay/tamper/forgery
  attacks; offline/recovered email; DNS drift and failure; key rotation; manual approval;
  signed feeds; self-update; server key rotation; roles and 2FA; decommission; cleanup;
  backup/restore.
- `sabotage.sh` — breaks one defense on purpose and confirms its test turns red, e.g.

  ```bash
  ./sabotage.sh "server forgets nonces" "replayed request rejected" src/wire.php \
    "        db_exec('INSERT INTO seen_nonces(nonce, at) VALUES(?, ?)', [\$nonce, time()]);" "        // off"
  ```

Under the hood the test router stands in for a reverse proxy (`fake_remote`)
so tests can choose which address the server "sees".
