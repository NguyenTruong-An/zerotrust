#!/bin/sh
set -eu
for item in mysql:999 redis:999 keycloak:65532 installer:65532 risk:10001 backend:10001 gateway:10001 migrate:10001 ingress:101 crl:101; do
    role=${item%:*}
    uid=${item#*:}
    test -d "/in/$role"
    cp -R "/in/$role/." "/out/$role/"
    chown -R "$uid:$uid" "/out/$role"
    find "/out/$role" -type d -exec chmod 700 {} +
    find "/out/$role" -type f -exec chmod 600 {} +
done
