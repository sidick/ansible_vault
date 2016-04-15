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
      - C(renew) renews a lease associated with a token. This is used to prevent the expiration of a token, and the automatic revocation of it. Token renewal is possible only if there is a lease associated with it
      - C(revoke) revokes a token and all child tokens. When the token is revoked, all secrets generated with it are also revoked
    required: true
    default: null
    choices: ['present', 'renew', 'revoke']
  mode:
    description:
      - Select type of blah
    required: false
    default: normal
    choices: ['normal', 'self', 'orphan', 'path']
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


def make_vault_url(vault_server, vault_port, vault_tls):
    """ Create base Vault URL """
    vault_url = ''
    if vault_tls:
        vault_url = 'https://'
    else:
        vault_url = 'http://'

    vault_url = vault_url + vault_server + ':' + str(vault_port)

    return vault_url


def get_auth_token(module, url, id):
    """ Get details for a named token """
    auth_url = url + '/v1/auth/token/lookup/' + id
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, auth_url, method='GET', headers=headers)

    if info['status'] != 200:
        return False
        module.fail_json(msg="Unable to fetch auth backend list ({0!s})".format(info['msg']))

    return json.loads(response.read())


def token_present(module, url):
    """ Make sure token is present """
    auth_url = url + '/v1/auth/token/create'
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'display_name': module.params['display_name'],
        'no_parent': module.params['no_parent'],
        'num_uses': module.params['num_uses'],
        'no_default_policy': module.params['no_default_policy']
    }

    if module.params['ttl'] != '':
        data['ttl'] = module.params['ttl']

    if module.params['policies']:
        policy_list = "['" + "', '".join(module.params['policies']) + "']"
        #data['policies'] = policy_list

    if module.params['id']:
        data['id'] = module.params['id']

        token_details = get_auth_token(module, url, module.params['id'])

        # If token already exists return unchanged
        if token_details:
            module.exit_json(changed=False, **token_details['data'])

    data_json = json.dumps(data)
    #module.fail_json(msg="%s" % data_json)

    response, info = fetch_url(module, auth_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to create token '{0!s}' ({1!s})".format(module.params['id'], info['msg']))

    ret = json.loads(response.read())

    module.exit_json(changed=True, **ret['auth'])


def token_renew_self(module, url):
    """ Renew authenticated token """
    renew_url = url + '/v1/auth/token/renew-self'

    headers = {"X-Vault-Token": module.params['token']}
    data = {}

    data_json = json.dumps(data)

    response, info = fetch_url(module, renew_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
      ret = json.loads(response.read())
      module.fail_json(msg="Unable to renew token, can't be found or is not renewable")

    ret = json.loads(response.read())

    module.exit_json(changed=True, **ret['auth'])


def token_renew(module, url):
    """ Renew token """

    renew_mode = module.params['mode']
    if renew_mode == 'self':
      token_renew_self(module, url)
def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True, choices=[ 'present',
                                                'renew',
                                                'revoke'
                                            ]),
            id=dict(required=False, default=None, type='str'),
            policies=dict(required=False, default=None, type='list'),
            mode=dict(required=False, default='normal', choices=['normal',
                                                                 'orphan',
                                                                 'path',
                                                                 'self'
            ]),
            no_parent=dict(required=False, default=False, type='bool'),
            no_default_policy=dict(required=False, default=False, type='bool'),
            ttl=dict(required=False, default='', type='str'),
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

    url = make_vault_url(vault_server, vault_port, vault_tls)

    if state == 'present':
        token_present(module, url)
    if state == 'renew':
        token_renew(module, url)



from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
