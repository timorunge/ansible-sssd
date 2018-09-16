#!/bin/sh
set -e

test -z ${sssd_from_sources} && echo "Missing environment variable: sssd_from_sources" && exit 1
(test "${sssd_from_sources}" = "true" && test -z ${sssd_version}) && echo "Missing environment variable: sssd_version" && exit 1

printf "[defaults]\nroles_path=/etc/ansible/roles\n" > /ansible/ansible.cfg

ansible-lint /ansible/test.yml
ansible-lint /etc/ansible/roles/${ansible_role}/tasks/main.yml

ansible-playbook /ansible/test.yml \
  -i /ansible/inventory \
  --syntax-check \
  -e "{ sssd_from_sources: ${sssd_from_sources} }" \
  -e "{ sssd_version: ${sssd_version} }"

ansible-playbook /ansible/test.yml \
  -i /ansible/inventory \
  --connection=local \
  --become \
  -e "{ sssd_from_sources: ${sssd_from_sources} }" \
  -e "{ sssd_version: ${sssd_version} }" \
  $(test -z ${travis} && echo "-vvvv")

ansible-playbook /ansible/test.yml \
  -i /ansible/inventory \
  --connection=local \
  --become \
  -e "{ sssd_from_sources: ${sssd_from_sources} }" \
  -e "{ sssd_version: ${sssd_version} }" | \
  grep -q "changed=0.*failed=0" && \
  (echo "Idempotence test: pass" && exit 0) || \
  (echo "Idempotence test: fail" && exit 1)

if [ "true" = "${sssd_from_sources}" ] ; then
  real_sssd_version=$(sssd --version 2>&1)
  test "${real_sssd_version}" = "${sssd_version}" && \
    (echo "SSSD version test: pass" && exit 0) || \
    (echo "SSSD version test: fail" && exit 1)
fi
