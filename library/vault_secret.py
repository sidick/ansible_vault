#!/usr/bin/python

import json
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

DOCUMENTATION = '''
---
module: vault_secret
short_description: Create, update and remove secrets
description:
  - Create, update and remove secrets
options:
  token:
    description:
      - Authentication token
    required: true
  state:
    description:
      - Allows you to specify whether the named secret should be
      - C(present) or C(absent)
    required: true
    default: null
    choices: ['present', 'absent']
  secret:
    description:
      - The path of the secret
    required: true
    default: null
  value:
    description:
      - The contents of the secret, obviously this is only
      - relevant when state=present
    required: false
    default: null
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
# Make sure a secret exists

- vault_secret:
    token: XXXXXXXX
    state: present
    secret: secret/foo
    key:
      user: username1
      pass: password1

# Remove a secret exists

- vault_secret:
    token: XXXXXXXX
    state: absent
    secret: secret/foo
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


def vault_secret_exist(module, url, token, secret):
    """ Check if a secret exists """
    secret_url = url + '/v1/' + secret
    headers = {"X-Vault-Token": token}

    response, info = fetch_url(module,
                               secret_url,
                               method='GET',
                               headers=headers)

    if info['status'] == 200:
        return True
    return False


def vault_set(module, url, token, secret, key):
    """ Set a Vault secret """
    secret_url = url + '/v1/' + secret
    headers = {"X-Vault-Token": token}

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module,
                               secret_url,
                               method='POST',
                               headers=headers,
                               data=json.dumps(key))

    if info['status'] != 200 and info['status'] != 204:
        module.fail_json(
            msg="Failed to write secret ({0!s})".format(
                info['msg'])
            )

    module.exit_json(changed=True)


def vault_remove(module, url, token, secret):
    """ Delete a secret """
    secret_url = url + '/v1/' + secret
    headers = {"X-Vault-Token": token}

    response, info = fetch_url(module,
                               secret_url,
                               method='DELETE',
                               headers=headers)

    if info['status'] != 200 and info['status'] != 204:
        module.fail_json(
            msg="Failed to remove secret ({0!s})".format(
                info['msg'])
            )

    module.exit_json(changed=True)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(required=True, choices=['present', 'absent']),
            token=dict(required=True, default=None, type='str'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool'),
            secret=dict(required=True, default=None, type='str'),
            key=dict(required=False, default=None, type='dict')
        ),
        supports_check_mode=True,
    )

    state = module.params['state']
    token = module.params['token']
    key = module.params['key']
    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']
    secret = module.params['secret']
    key = module.params['key']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    if state == 'present':
        vault_set(module, url, token, secret, key)
    if state == 'absent':
        if (vault_secret_exist(module, url, token, secret)):
            vault_remove(module, url, token, secret)
        else:
            return module.exit_json(changed=False)

    return module.fail_json(msg="Unknown usage absent = {0!s}".format(state))


main()
