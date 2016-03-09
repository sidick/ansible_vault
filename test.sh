#!/bin/bash

vault server -dev >.test_output&
sleep 1

export UNSEAL_KEY=`grep 'Unseal Key' .test_output  | sed 's#^.*: ##'`
export AUTH_TOKEN=`grep 'Root Token' .test_output | sed 's#^.*: ##'`

source ~/src/ansible/hacking/env-setup -q

~/src/ansible/hacking/test-module -m vault_seal.py -a "state=sealed tls=no token=${AUTH_TOKEN}"

killall vault
rm -f .test_output
