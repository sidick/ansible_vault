#!/usr/bin/python

import json
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

DOCUMENTATION = '''
---
module: vault_seal
short_description: Seal and Unseal Vault
description:
  - Seal and Unseal Vault
options:
  token:
    description:
      - Authentication token
    required: true
  key:
    description:
      - Decryption key
    required: false
  state:
    description:
      - Lets you set the state of the vault
      - C(sealed) seals the vault
      - C(unsealed) lets you pass in a decryption key to the unseal process
      - C(reset) resets the unseal process and discards any previously set keys
    required: true
    default: null
    choices: ['sealed', 'unsealed', 'reset']
  server:
    description:
      - Hostname used to connect to the Vault server
    required: false
    default: localhost
  port:
    description:
      - Port used to connect to the Vault server
    required: false
    default: 8200
  tls:
    description:
      - Whether TLS is used to connect to the Vault server
      - C(yes) sets the use of TLS
      - C(no) disables the use of TLS
    required: false
    default: 'yes'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only
      - be used on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
'''

EXAMPLES = '''
# Seal the vault

- vault_seal:
    token: XXXXXXXX
    state: sealed

# Unseal the vault

- vault_seal:
    state: unsealed
    key: XXXXXX

# Reset the unseal process

- vault_seal:
    token: XXXXXXXX
    state: reset
'''


def make_vault_url(vault_server, vault_port, vault_tls):
    """ Create base Vault URL """
    vault_url = ''
    if vault_tls:
        vault_url = 'https://'
    else:
        vault_url = 'http://'

    vault_url = vault_url + vault_server + ':' + str(vault_port)

    return vault_url


def vault_seal(module, url, token):
    """ Seal the Vault """
    seal_url = url + '/v1/sys/seal'
    headers = {"X-Vault-Token": token}

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module,
                               seal_url,
                               method='POST',
                               headers=headers)

    if info['status'] != 200 and info['status'] != 204:
        module.fail_json(msg="Failed to seal vault")

    module.exit_json(changed=True)


def vault_unseal(module, url, key):
    """ Apply an unseal key to the Vault """
    unseal_url = url + '/v1/sys/unseal'
    data = json.dumps({'key': key})

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module, unseal_url, method='POST', data=data)

    if info['status'] != 200 and info['status'] != 204:
        module.fail_json(
            msg="Unable to unseal vault ({0!s})".format(
                info['msg'])
            )

    result = json.loads(response.read())

    module.exit_json(changed=True, **result)


def vault_seal_status(module, url):
    """ Return the status of the Vault """
    seal_url = url + '/v1/sys/seal-status'

    response, info = fetch_url(module, seal_url, method='GET')

    if info['status'] == 200:
        return json.loads(response.read())

    module.fail_json(
        msg="Failed to get vault status ({0!s})".format(
            info['msg'])
        )


def vault_reset(module, url, token):
    """ Reset the Vault unseal process """
    reset_url = url + '/v1/sys/unseal'
    headers = {"X-Vault-Token": token}
    data = json.dumps({'reset': True})

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module,
                               reset_url,
                               method='POST',
                               headers=headers,
                               data=data)

    if info['status'] != 200 and info['status'] != 204:
        module.fail_json(
            msg="Unable to reset vault unseal ({0!s})".format(
                info['msg'])
            )

    result = json.loads(response.read())

    module.exit_json(changed=True, **result)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(required=True, choices=['sealed', 'unsealed', 'reset']),
            token=dict(required=False, default=None, type='str'),
            key=dict(required=False, default=None, type='str'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool')
        ),
        supports_check_mode=True,
    )

    state = module.params['state']
    token = module.params['token']
    key = module.params['key']
    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    seal_state = vault_seal_status(module, url)

    if state == 'sealed':
        if not seal_state['sealed']:
            vault_seal(module, url, token)
        else:
            module.exit_json(changed=False)
    if state == 'unsealed':
        if seal_state['sealed']:
            vault_unseal(module, url, key)
        else:
            module.exit_json(changed=False)
    if state == 'reset':
        if seal_state['sealed']:
            vault_reset(module, url, token)
        else:
            module.exit_json(changed=False, msg="Vault already unsealed")

    return module.fail_json(msg="Unknown usage")


main()
