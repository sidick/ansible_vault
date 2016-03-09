ci:
	./scripts/ci_setup.sh

test:
	ansible-playbook -i ./hosts test-vault.yml

.PHONY: ci
