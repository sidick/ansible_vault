#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_facts
short_description: Retrieve Facts about Vault
description:
  - Retrieve Facts about Vault
options:
  token:
    description:
      - Authentication token - If this isn't provided only things like Seal Status and HA Status will be populated
    required: false
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
      - If C(no), SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
'''

EXAMPLES = '''
# Conditional example
- name: Gather facts
  action: vault_facts

- name: Conditional
  action: debug msg="This vault is sealed"
  when: vault_sealed
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


def vault_seal_status(module, url):
    """ Return the Vault seal status """
    seal_url = url + '/v1/sys/seal-status'

    response, info = fetch_url(module, seal_url, method='GET')

    if info['status'] == 200:
        return json.loads(response.read())

    module.fail_json(msg="Failed to get vault status ({0!s})".format(info['msg']))


def get_list(module, url, type):
    """ Get the list of objects at a particular url """
    api_url = url + '/v1/sys/' + type
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, api_url, method='GET', headers=headers)

    if info['status'] != 200:
        module.fail_json(msg="Unable to fetch {0!s} list ({1!s})".format(type, info['msg']))

    return json.loads(response.read())


def vault_leader_status(module, url):
    """ Get the Vault leader status """
    seal_url = url + '/v1/sys/leader'

    response, info = fetch_url(module, seal_url, method='GET')

    if info['status'] == 200:
        return json.loads(response.read())

    module.fail_json(msg="Failed to get vault leader status ({0!s})".format(info['msg']))


def vault_facts(module, url):
    """ Combine all the Vault facts and return the data """
    results1 = vault_seal_status(module, url)
    results2 = vault_leader_status(module, url)

    results = dict(results1, **results2)

    if module.params['token']:
        results['mounts'] = get_list(module, url, 'mounts')
        results['audit'] = get_list(module, url, 'audit')
        results['auth'] = get_list(module, url, 'auth')
        results['policies'] = get_list(module, url, 'policy')['policies']

    module.exit_json(changed=False, **results)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=False, default=None, type='str'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool')
        ),
        supports_check_mode=True,
    )

    token = module.params['token']
    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    vault_facts(module, url)

    return module.fail_json(msg="Can't gather Vault facts")


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
