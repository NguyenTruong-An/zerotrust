#!/bin/bash
set -eu
export KC_BOOTSTRAP_ADMIN_USERNAME=demo-bootstrap
export KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/demo/bootstrap-password)"
export JAVA_OPTS_APPEND="@/run/demo/jvm.args -Xmx384m"
mkdir -p /opt/keycloak/data/import
cp /run/demo/realm/demo-realm.json /opt/keycloak/data/import/zerotrust-demo-realm.json
exec /opt/keycloak/bin/kc.sh --config-file=/run/demo/keycloak.conf start --optimized --import-realm
