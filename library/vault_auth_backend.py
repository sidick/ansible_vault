#!/usr/bin/python

import json
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *


DOCUMENTATION = '''
---
module: vault_auth_backend
short_description: Manage Vault Authentication Backends
description:
  - Add and Remove Vault authentication backends
options:
  token:
    description:
      - Authentication token
    required: true
  state:
    description:
      - Lets you set the state of the authentication backend
      - C(present) mounts the backend
      - C(absent) lets you unmount the backend
    required: true
    default: null
    choices: ['present', 'absent']
  mountpoint:
    description:
      - Specifies the name of the mountpoint
    required: true
    default: null
  type:
    description:
      - Sets the type of the mountpoint from the list at
      - https://www.vaultproject.io/docs/auth/index.html
    required: false
    default: null
  description:
    description:
      - Sets a human-friendly description of the mount
    require: false
    default: ''
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
      - If C(no), SSL certificates will not be validated. This should only be
      - used on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
'''

EXAMPLES = '''
# Enable a new auth backend

- vault_auth_backend:
    token: XXXXXXXX
    state: present
    mountpoint: app-id
    type: app-id
    description: 'App-ID Authentication'

# Disable an auth backend

- vault_auth_backend:
    token: XXXXXXXX
    mountpoint: app-id
    state: absent

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


def get_auth_backends(module, url):
    """ Get the list of auth backends """
    auth_url = url + '/v1/sys/auth'
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, auth_url, method='GET', headers=headers)

    if info['status'] != 200:
        module.fail_json(
            msg="Unable to fetch auth backend list ({0!s})".format(
                info['msg'])
            )

    return json.loads(response.read())


def auth_present(module, url):
    """ Make sure the auth backend is present """
    auth_url = url + '/v1/sys/auth/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'type': module.params['type'],
        'description': module.params['description'],
    }
    data_json = json.dumps(data)

    auth_list = get_auth_backends(module, url)

    if module.params['mountpoint']+'/' in auth_list:
        module.exit_json(changed=False, **data)

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module,
                               auth_url,
                               method='POST',
                               headers=headers,
                               data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(
            msg="Unable to enable auth backend '{0!s}' ({1!s})".format(
                module.params['mountpoint'], info['msg'])
            )

    module.exit_json(changed=True, **data)


def auth_absent(module, url):
    """ Make sure the auth backend is absent """
    auth_url = url + '/v1/sys/auth/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    auth_list = get_auth_backends(module, url)

    if module.params['mountpoint']+'/' not in auth_list:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    response, info = fetch_url(module,
                               auth_url,
                               method='DELETE',
                               headers=headers)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(
            msg="Unable to disable auth backend '{0!s}' ({1!s})".format(
                module.params['mountpoint'], info['msg'])
            )

    module.exit_json(changed=True)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True,
                       vchoices=['present', 'absent', 'remount']),
            mountpoint=dict(required=True, default=None, type='str'),
            type=dict(required=False, default=None, type='str'),
            description=dict(required=False, default='', type='str'),
            server=dict(required=False, default='localhost', type='str'),
            port=dict(required=False, default=8200, type='int'),
            tls=dict(required=False, default=True, type='bool'),
            validate_certs=dict(required=False, default=True, type='bool')
        ),
        supports_check_mode=True,
    )

    state = module.params['state']
    token = module.params['token']
    vault_port = module.params['port']
    vault_server = module.params['server']
    vault_tls = module.params['tls']

    url = make_vault_url(vault_server, vault_port, vault_tls)

    if state == 'present':
        auth_present(module, url)
    if state == 'absent':
        auth_absent(module, url)


main()
