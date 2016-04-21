ansible-vault
=============

Branch | Travis Status | Code Issues
-------|-------|----
master | [![Build Status](https://travis-ci.org/sidick/ansible_vault.svg?branch=master)](https://travis-ci.org/sidick/ansible_vault) | [![Code Issues](https://www.quantifiedcode.com/api/v1/project/d9069ae56d9e4dd890ba6046345530a9/snapshot/origin:master:HEAD/badge.svg)](https://www.quantifiedcode.com/app/project/d9069ae56d9e4dd890ba6046345530a9)

ansible-vault is a way of providing a number of Ansible modules to make working
with [Ansible] and [Vault]

Currently the modules available include:

* vault_audit_backend
* vault_auth
* vault_auth_backend
* vault_facts
* vault_mount
* vault_policy
* vault_secret
* vault_seal

They can be used by copying the contents of the library directory to the library
directory in which you're working.

I haven't written a lookup plugin, but there is one at
<https://github.com/jhaals/ansible-vault>

Author
======
Simon Dick - <simond@irrelevant.org>

[Ansible]: https://www.ansible.com/ "Automation For Everyone"
[Vault]: https://www.vaultproject.io/ "A tool for managing secrets"
