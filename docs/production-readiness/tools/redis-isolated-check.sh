#!/bin/sh
# Run ONLY in a disposable network-none Redis container with tmpfs /tmp.
# /audit/failure-store.lua must be extracted verbatim from the baseline Java text block.
set -eu
redis-server --port 0 --unixsocket /tmp/audit.sock --save '' --appendonly no --daemonize yes --dir /tmp --logfile /tmp/redis.log
cli() { redis-cli -s /tmp/audit.sock --raw "$@"; }
eval_failure() { cli --eval /audit/failure-store.lua "$1" "$2" "$3" , 3600 900; }
[ "$(eval_failure event-1 subject ip)" = 1 ]
[ "$(eval_failure event-1 subject ip)" = 0 ]
[ "$(cli GET subject)" = 1 ]
[ "$(cli GET ip)" = 1 ]
[ "$(cli TTL event-1)" -gt 3500 ]
[ "$(cli TTL subject)" -gt 850 ]
cli SET subject invalid >/dev/null
result=$(eval_failure event-2 subject ip)
case "$result" in *'counter cannot be incremented'*) ;; *) exit 1;; esac
[ "$(cli EXISTS event-2)" = 0 ]
[ "$(cli GET ip)" = 1 ]
cli SET subject 9223372036854775807 >/dev/null
result=$(eval_failure event-3 subject ip)
case "$result" in *'counter cannot be incremented'*) ;; *) exit 1;; esac
[ "$(cli EXISTS event-3)" = 0 ]
cli SET subject 1 >/dev/null
cli EXPIRE subject 5 >/dev/null
eval_failure event-4 subject ip >/dev/null
[ "$(cli TTL subject)" -le 5 ]
[ "$(cli GET subject)" = 2 ]
echo '{"engine":"Redis 7.4.7","isolation":"network none; tmpfs; no Lab mounts","cases":7,"result":"PASS","scope":["first increment","event dedup","counter and event TTL","malformed counter no partial write","int64 overflow no partial write","fixed first-failure TTL not refreshed","counter increment after prior event"]}'
cli SHUTDOWN NOSAVE
