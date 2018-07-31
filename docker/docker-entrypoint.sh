#!/bin/sh
set -e

printf '[defaults]\nroles_path=/etc/ansible/roles' > ansible.cfg
ansible-lint /etc/ansible/roles/${ENV_ROLE_NAME}/tasks/main.yml
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --syntax-check
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --connection=local --become $(test -z ${TRAVIS} && echo '-vvvv')
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --connection=local --become | grep -q 'changed=0.*failed=0' && (echo 'Idempotence test: pass' && exit 0) || (echo 'Idempotence test: fail' && exit 1)
true
service sssd status && (echo 'Service status test: pass' && exit 0) || (echo 'Service status test: fail' && exit 1)
service sssd restart && (echo 'Service restart test: pass' && exit 0) || (echo 'Service restart test: fail' && exit 1)
