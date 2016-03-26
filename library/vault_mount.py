#!/usr/bin/python

import json

DOCUMENTATION = '''
---
module: vault_mount
short_description: Add and Remove Vault mounts
description:
  - Add and Remove Vault mounts
options:
  token:
    description:
      - Authentication token
    required: true
  state:
    description:
      - Lets you set the state of the mount point
      - C(present) mounts the backend
      - C(absent) lets you unmount the backend
      - C(remount) lets you remount an existing mountpoint to a new mountpoint
    required: true
    default: null
    choices: ['present', 'absent', 'remount']
  mountpoint:
    description:
      - Specifies the name of the mountpoint
    required: true
    default: null
  new_mountpoint:
    description:
      - Specifies the name of the new mountpoint when remounting
    required: false
    default: null
  type:
    description:
      - Sets the type of the mountpoint from the list at https://www.vaultproject.io/docs/secrets/index.html
    required: false
    default: null
  description:
    description:
      - Sets a human-friendly description of the mount
    require: false
    default: ''
  default_lease_ttl:
    description:
      - The default time-to-live
    required: false
    default: 0
  max_lease_ttl:
    description:
      - The maximum time-to-live
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
# Mount a backend

- vault_mount:
    token: XXXXXXXX
    state: present
    type: aws
    description: 'AWS Backend'
    mountpoint: aws

# Unmount a backend

- vault_mount:
    token: XXXXXXXX
    state: absent
    mountpoint: aws

# Remount a backend

- vault_mount:
    token: XXXXXXXX
    state: remount
    mountpoint: aws
    new_mountpoint: aws2

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


def get_mounts(module, url):
    """ Get the list of secret mounts """
    mount_url = url + '/v1/sys/mounts'
    headers = {"X-Vault-Token": module.params['token']}

    response, info = fetch_url(module, mount_url, method='GET', headers=headers)

    if info['status'] != 200:
        module.fail_json(msg="Unable to fetch mount list ({0!s})".format(info['msg']))

    return json.loads(response.read())


def mount_present(module, url):
    """ Make sure a secret mount is mounted """
    mount_url = url + '/v1/sys/mounts/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'type': module.params['type'],
        'description': module.params['description'],
        'config': {
            'default_lease_ttl': str(module.params['default_lease_ttl']),
            'max_lease_ttl': str(module.params['max_lease_ttl'])
        }
    }
    data_json = json.dumps(data)

    mount_list = get_mounts(module, url)

    if module.params['mountpoint']+'/' in mount_list:
        # TODO: Add code in here to change the lease parameters
        module.exit_json(changed=False, **data)

    response, info = fetch_url(module, mount_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to mount '{0!s}' ({1!s})".format(module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True, **data)


def mount_absent(module, url):
    """ Make sure a secret mount is not mounted """
    mount_url = url + '/v1/sys/mounts/' + module.params['mountpoint']
    headers = {"X-Vault-Token": module.params['token']}

    mount_list = get_mounts(module, url)

    if module.params['mountpoint']+'/' not in mount_list:
        module.exit_json(changed=False)

    response, info = fetch_url(module, mount_url, method='DELETE', headers=headers)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to unmount '{0!s}' ({1!s})".format(module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True)


def mount_remount(module, url):
    """ Change the mountpoint of a secret mount """
    mount_url = url + '/v1/sys/remount'
    headers = {"X-Vault-Token": module.params['token']}

    data = {
        'from': module.params['mountpoint'],
        'to': module.params['new_mountpoint']
    }

    data_json = json.dumps(data)

    mount_list = get_mounts(module, url)

    if module.params['mountpoint']+'/' not in mount_list:
        module.fail_json(msg="Mountpoint '{0!s}' not available to remount".format(module.params['mountpoint']))

    if module.params['new_mountpoint']+'/' in mount_list:
        module.fail_json(msg="New mountpoint already exists: {0!s}".format(module.params['new_mountpoint']))

    response, info = fetch_url(module, mount_url, method='POST', headers=headers, data=data_json)

    if info['status'] != 204 and info['status'] != 200:
        module.fail_json(msg="Unable to remount '{0!s}' ({1!s})".format(module.params['mountpoint'], info['msg']))

    module.exit_json(changed=True, msg="blah", **data)


def main():
    """ Main module function """

    module = AnsibleModule(
        argument_spec=dict(
            token=dict(required=True, default=None, type='str'),
            state=dict(required=True, choices=['present', 'absent', 'remount']),
            mountpoint=dict(required=True, default=None, type='str'),
            new_mountpoint=dict(required=False, default=None, type='str'),
            type=dict(required=False, default=None, type='str'),
            description=dict(required=False, default='', type='str'),
            default_lease_ttl=dict(required=False, default=0, type='int'),
            max_lease_ttl=dict(required=False, default=0, type='int'),
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
        mount_present(module, url)
    if state == 'absent':
        mount_absent(module, url)
    if state == 'remount':
        mount_remount(module, url)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

main()
