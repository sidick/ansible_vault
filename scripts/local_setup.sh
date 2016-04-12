#!/bin/bash
#
# Use a preinstalled copy of Vault to run tests on
#
set -ev

vault server -config=data/vault.hcl >/tmp/vault_output_full &
vault server -dev >/tmp/vault_output &

sleep 1

# vim: ft=sh:
