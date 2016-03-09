#!/bin/bash
#
# Install and set up consul to run server for tests
#
set -ev

VAULT_VER=0.5.1
VAULT_DL_URL=https://releases.hashicorp.com/vault/${VAULT_VER}/vault_${VAULT_VER}_linux_amd64.zip

curl -L $VAULT_DL_URL > vault.zip
unzip -o vault.zip -d $PWD/bin/
chmod +x $PWD/bin/vault

export PATH=$PATH:$PWD/bin

vault server -dev >/tmp/vault_output &

sleep 1

# vim: ft=sh:
