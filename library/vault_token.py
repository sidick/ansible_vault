#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_token
short_description: Manage Vault Authentication Tokens
description:
  - Add and Remove Vault authentication tokens
options:
  token:
    description:
      - Authentication token
    required: true
  state:
    description:
      - Lets you set the state of the authentication token
      - C(present) makes sure the token exists
      - C(absent) makes sure the token doesn't exist
    required: true
    default: null
    choices: ['present', 'absent']
  id:
    description:
      - The requested ID of the token, this can only be used when authenticating using a root token
    required: false
  policies:
    description:
      - A list of policies for the token. This must be a subset of the policies belonging to the token making the request, unless root. If not specified, defaults to all the policies of the calling token
    required: false
    default: []
  no_parent:
    description:
      - If true and set by a root caller, the token will not have the parent token of the caller. This creates a token with no parent
    required: false
    default: False
  no_default_policy:
    description:
      - If true the default policy will not be a part of this token's policy set
    required: false
    default: False
  ttl:
    description:
      - The TTL period of the token, provided as "1h", where hour is the largest suffix. If not provided, the token is valid for the default lease TTL, or indefinitely if the root policy is used
    required: false
    aliases: ['lease']
  display_name:
    description:
      - The display name of the token
    required: false
    default: 'token'
  num_uses:
    description:
      - The maximum uses for the given token. This can be used to create a one-time-token or limited use token. Defaults to 0, which has no limit to number of uses
    required: false
    default: 0
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
# Create a new auth token

- vault_token:
    token: XXXXXXXX
    state: present

# Disable an auth backend

- vault_token:
    token: XXXXXXXX

'''


def make_vault_url(module, vault_server, vault_port, vault_tls):
    vault_url = ''
    if vault_tls:
        vault_url = 'https://'
    else:
        vault_url = 'http://'

    vault_url = vault_url + vault_server + ':' + str(vault_port)

    return vault_url


def get_auth_token(module, url, id):
    auth_url = url + '/v1/auth/token/lookup/' + id
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, auth_url, method='GET', headers=headers)

    if info['status'] != 200:
        return False
        module.fail_json(msg="Unable to fetch auth backend list (%s)" % info['msg'])

    return json.loads(response.read())


def token_present(module, url):
    auth_url = url + '/v1/auth/token/create'
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'display_name': module.params['display_name'],
        'ttl': module.params['ttl'],
    }
    data_json = json.dumps(data)

    token_details = get_auth_token(module, url, module.params['id'])

    # If token already exists return unchanged
    if token_details:
        module.exit_json(change=False, **token_details)

    response, info = fetch_url(module, auth_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to create token '%s' (%s)" % (module.params['id'], info['msg']))

    module.exit_json(changed=True, **data)


def token_absent(module, url):
    token_url = url + '/v1/sys/auth/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    token_list = get_auth_backends(module, url)

    if module.params['mountpoint']+'/' not in auth_list:
        module.exit_json(change=False)

    response, info = fetch_url(module, auth_url, method='DELETE', headers=headers)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to disable auth backend '%s' (%s)" % (module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True, choices=['present', 'absent', 'remount']),
            id=dict(required=False, default=None, type='str'),
            policies=dict(required=False, default=None, type='dict'),
            no_parent=dict(required=False, default=False, type='bool'),
            no_default_policy=dict(required=False, default=False, type='bool'),
            ttl=dict(required=False, default=None, type='str'),
            display_name=dict(required=False, default='token', type='str'),\
            num_uses=dict(required=False, default=0, type='int'),
            server=dict(required=False, default='localhost', type='str'),
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

    url = make_vault_url(module, vault_server, vault_port, vault_tls)

    if state == 'present':
        token_present(module, url)
    if state == 'absent':
        auth_absent(module, url)



from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
