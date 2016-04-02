#!/usr/bin/python

import json
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

DOCUMENTATION = '''
---
module: vault_init
short_description: Initialises Vault
description:
  - Initialises Vault if it hasn't already been initialised
options:
  shares:
    description:
      - The number of shares to split the master key into
    required: true
  threshold:
    description:
      - The number of shares required to reconstruct the
      - master key. This must be less than or equal to shares
    required: true
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

- vault_init:
    shares: 5
    threshold: 3
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


def check_vault_is_initialised(module, url):
    """ Check if Vault is initialised """

    api_url = url + '/v1/sys/init'

    response, info = fetch_url(module, api_url, method='GET')

    ret = json.loads(response.read())
    if ret['initialized']:
        return True

    return False


def vault_init(module, url):
    """ Initialise Vault if needed, otherwise just return """

    init_url = url + '/v1/sys/init'

    if check_vault_is_initialised(module, url):
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    data = {
        'secret_shares': module.params['shares'],
        'secret_threshold': module.params['threshold'],
        'pgp_keys': None
    }

    data_json = json.dumps(data)

    response, info = fetch_url(module, init_url, method='PUT', data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(
            msg="Unable to initialise Vault ({0!s})".format(
                info['msg'])
            )

    ret = json.loads(response.read())
    module.exit_json(changed=True, **ret)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            shares=dict(required=True, default=None, type='int'),
            threshold=dict(required=True, default=None, type='int'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool'),
        ),
        supports_check_mode=True,
    )

    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    vault_init(module, url)

    return module.fail_json(msg="Unknown usage absent = {0!s}".format(state))


main()
