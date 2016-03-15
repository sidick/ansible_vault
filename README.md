ansible-vault
=============

Branch | Status
-------|-------
master | [![Build Status](https://travis-ci.org/sidick/ansible_vault.svg?branch=master)](https://travis-ci.org/sidick/ansible_vault)
devel | [![Build Status](https://travis-ci.org/sidick/ansible_vault.svg?branch=master)](https://travis-ci.org/sidick/ansible_vault)

ansible-vault is a way of providing a number of Ansible modules to make working
with [Ansible] and [Vault]

Currently the modules available include:

* vault_facts
* vault_mount
* vault_secret
* vault_seal

They can be used by copying the contents of the library directory to the library
directory in which you're working.

Author
======
Simon Dick - <simond@irrelevant.org>

[Ansible]: https://www.ansible.com/ "Automation For Everyone"
[Vault]: https://www.vaultproject.io/ "A tool for managing secrets"
