#!/bin/sh
set -eu
for item in mysql:999 redis:999 keycloak:1000 installer:1000 risk:10001 backend:10001 gateway:10001 migrate:10001 ingress:101; do
    role=${item%:*}
    uid=${item#*:}
    if [ "$#" -gt 0 ] && [ "$1" != "$role" ]; then continue; fi
    test -d "/in/$role"
    cp -R "/in/$role/." "/out/$role/"
    chown -R "$uid:$uid" "/out/$role"
    find "/out/$role" -type d -exec chmod 700 {} +
    find "/out/$role" -type f -exec chmod 600 {} +
done
