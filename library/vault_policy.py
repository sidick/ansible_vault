#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_policy
short_description: Add and Remove Vault policies
description:
  - Add and Remove Vault policies
options:
  token:
    description:
      - Authentication token
    required: true
  state:
    description:
      - Lets you set the state of the policy
      - C(present) makes sure the policy is present
      - C(absent) makes sure the policy isn't present
    required: true
    default: null
    choices: ['present', 'absent']
  policy_name:
    description:
      - The name of the policy
    required: true
  policy:
    description:
      - The policy to create
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
# Create a backend

- vault_policy:
    token: XXXXXXXX
    state: present
    policy_name: policyname

# Remove a policy

- vault_policy:
    token: XXXXXXXX
    state: absent
    policy_name: policyname

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


def get_policies(module, url):
    """ Get the list of policies that are setup """
    policy_url = url + '/v1/sys/policy'
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, policy_url, method='GET', headers=headers)

    if info['status'] != 200:
        module.fail_json(msg="Unable to fetch policy list ({0!s})".format(info['msg']))

    return json.loads(response.read())


def policy_present(module, url):
    """ Ensure a policy is present """
    policy_url = url + '/v1/sys/policy/' + module.params['policy_name']
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'rules': module.params['policy'],
    }
    data_json = json.dumps(data)

    response, info = fetch_url(module, policy_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to create policy '{0!s}' ({1!s})".format(module.params['policy'], info['msg']))

    module.exit_json(changed=True)


def policy_absent(module, url):
    """ Ensure a policy is absent """
    policy_url = url + '/v1/sys/policy/' + module.params['policy_name']
    headers = {"X-Vault-Token": module.params['token']}

    policy_list = get_policies(module, url)

    if module.params['policy_name'] not in policy_list['policies']:
        module.exit_json(changed=False)

    response, info = fetch_url(module, policy_url, method='DELETE', headers=headers)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to remove policy '{0!s}' ({1!s})".format(module.params['policy'], info['msg']))

    module.exit_json(changed=True)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True, choices=['present', 'absent']),
            server=dict(required=False, default='localhost', type='str'),
            policy_name=dict(required=True, default=None, type='str'),
            policy=dict(required=False, default=None, type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool')
        ),
        supports_check_mode=False,
    )

    state = module.params['state']
    token = module.params['token']
    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    if state == 'present':
        policy_present(module, url)
    if state == 'absent':
        policy_absent(module, url)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
