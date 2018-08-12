#!/bin/sh
set -e

test -z ${YML_TEST_FILE} && echo 'Missing environment variable: YML_TEST_FILE' && exit 1

printf '[defaults]\nroles_path=/etc/ansible/roles\ngather_timeout=60' > ansible.cfg
ansible-lint /etc/ansible/roles/${ENV_ROLE_NAME}/tasks/main.yml
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --syntax-check
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --connection=local --become $(test -z ${TRAVIS} && echo '-vvvv')
ansible-playbook ${ENV_WORKDIR}/${YML_TEST_FILE} -i ${ENV_WORKDIR}/inventory --connection=local --become | grep -q 'changed=0.*failed=0' && (echo 'Idempotence test: pass' && exit 0) || (echo 'Idempotence test: fail' && exit 1)

if [ "true" = "$(awk '/sssd_from_sources/{print $2}' ${ENV_WORKDIR}/${YML_TEST_FILE})" ] ; then
  REAL_SSSD_VERSION=$(sssd --version 2>&1)
  EXPECTED_SSSD_VERSION=$(awk '/sssd_version/{print $3}' ${ENV_WORKDIR}/${YML_TEST_FILE} | sed -e 's/_/./g')
  test "${REAL_SSSD_VERSION}" = "${EXPECTED_SSSD_VERSION}" && (echo 'SSSD version test: pass' && exit 0) || (echo 'SSSD version test: fail' && exit 1)
fi
