#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_auth
short_description: Create, update and remove secrets
description:
  - Create, update and remove secrets
options:
  token:
    description:
      - Authentication token
    required: true
  method:
    description:
      - Authentication method to use
    required: false
    default: 'token'
  auth:
    description:
      - List of key/value pairs to use to authenticate against the appropriate backend
    required: true
  no_verify:
    description:
      - Do not verify the token after creation; avoids a use count decrement
    required: false
    default: false
  secret:
    description:
      - The path of the secret
    required: true
    default: null
  value:
    description:
      - The contents of the secret, obviously this is only relevant when state=present
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
      - If C(no), SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
'''

EXAMPLES = '''
# Make sure a secret exists

- vault_auth:
    token: XXXXXXXX
    state: present
    secret: secret/foo
    key:
      user: username1
      pass: password1

# Remove a secret exists

- vault_auth:
    token: XXXXXXXX
    state: absent
    secret: secret/foo
'''


def make_vault_url(module, vault_server, vault_port, vault_tls):
    vault_url = ''
    if vault_tls:
        vault_url = 'https://'
    else:
        vault_url = 'http://'

    vault_url = vault_url + vault_server + ':' + str(vault_port)

    return vault_url


def vault_auth(module, url):

    auth_methods = {
        'github':   ['token'],
        'ldap':     ['username', 'password'],
        'userpass': ['username', 'password']
    }

    auth_url = url + '/v1/'

    method = module.params['method']
    auth = module.params['auth']

    data = {}

    if method in auth_methods:
        for param in auth_methods[method]:
            if param not in auth:
                module.fail_json(msg="%s is required for the %s method" % (param, method))

        data = auth
        auth_url = auth_url + 'auth/' + method + '/login'
        if 'username' in auth:
            auth_url = auth_url + '/' + auth['username']
            del data['username']

    else:
        module.fail_json(msg="Couldn't authenticate, unknown method")

    data_json = json.dumps(data)

    response, info = fetch_url(module, auth_url, method='POST', data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to authenticate (%s)" % info['msg'])

    ret = json.loads(response.read())
    module.exit_json(changed=True, **ret['auth'])


def main():

    module = AnsibleModule(
        argument_spec=dict(
            method=dict(required=True, default=None, type='str'),
            auth=dict(required=True, default=None, type='dict'),
            no_verify=dict(required=False, default=False, type='bool'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool'),
        ),
        supports_check_mode=False,
    )

    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(module, vault_server, vault_port, vault_tls)

    vault_auth(module, url)

    return module.fail_json(msg="Unknown usage absent = %s" % state)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
