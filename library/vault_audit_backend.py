#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_audit_backend
short_description: Manage Vault Audit Backends
description:
  - Add and Remove Vault Audit backends
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
      - Sets the type of the mountpoint from the list at https://www.vaultproject.io/docs/auth/index.html
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
      - If C(no), SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
'''

EXAMPLES = '''
# Enable a new audit backend

- vault_audit_backend:
    token: XXXXXXXX
    state: present
    mountpoint: app-id
    type: app-id
    description: 'App-ID Authentication'

# Disable an auth backend

- vault_audit_backend:
    token: XXXXXXXX
    mountpoint: app-id
    state: absent

'''


def make_vault_url(module, vault_server, vault_port, vault_tls):
    """ Create base Vault URL """

    vault_url = ''
    if vault_tls:
        vault_url = 'https://'
    else:
        vault_url = 'http://'

    vault_url = vault_url + vault_server + ':' + str(vault_port)

    return vault_url


def get_audit_backends(module, url):
    """ Fetch a list of audit backends which are enabled """

    auth_url = url + '/v1/sys/audit'
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, auth_url, method='GET', headers=headers)

    if info['status'] != 200:
        module.fail_json(msg="Unable to fetch audit backend list (%s)" % info['msg'])

    return json.loads(response.read())


def audit_present(module, url):
    """ Ensure audit backend is present """

    audit_url = url + '/v1/sys/audit/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    audit = {
        'file': ['path'],
        'syslog': [],
    }

    type = module.params['type']
    if type not in audit:
        module.fail_json(msg="Unsupported audit backend: %s" % type)

    for required in audit[type]:
        if not module.params[required]:
            module.fail_json(msg="%s is required for %s audit backend" % (required, type))

    options = {}
    if type == 'file':
        options['path'] = module.params['path']

    data = {
        'type': type,
        'description': module.params['description'],
        'options': options
    }

    data_json = json.dumps(data)

    audit_list = get_audit_backends(module, url)

    if module.params['mountpoint']+'/' in audit_list:
        module.exit_json(changed=False, **data)

    response, info = fetch_url(module, audit_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to enable auth backend '%s' (%s)" % (module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True, **data)


def audit_absent(module, url):
    """ Ensure audit backend is absent """

    audit_url = url + '/v1/sys/audit/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    audit_list = get_audit_backends(module, url)

    if module.params['mountpoint']+'/' not in audit_list:
        module.exit_json(changed=False)

    response, info = fetch_url(module, audit_url, method='DELETE', headers=headers)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to disable audit backend '%s' (%s)" % (module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True, choices=['present', 'absent', 'remount']),
            mountpoint=dict(required=True, default=None, type='str'),
            type=dict(required=False, default=None, type='str'),
            path=dict(required=False, default=None, type='str'),
            description=dict(required=False, default='', type='str'),
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
        audit_present(module, url)
    if state == 'absent':
        audit_absent(module, url)



from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
