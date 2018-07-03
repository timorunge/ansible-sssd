sssd
==============

This role is installing and configuring the SSSD service.

Requirements
------------

This role requires Ansible 2.4.0 or higher. It's fully tested with the latest
stable release (2.6.0).

You can simply use pip to install (and define) the latest stable version:

```sh
pip install ansible==2.6.0
```

All platform requirements are listed in the metadata file.

Install
-------

```sh
ansible-galaxy install timorunge.sssd
```

Role Variables
--------------

This role is basically building out of a YAML hierarchy an working configuration
file for the SSSD service. For a valid configuration take a look at the
[man pages](https://linux.die.net/man/5/sssd.conf).

```yaml
sssd_config:
  'domain/example.com':
    access_provider: permit
    auth_provider: local
    id_provider: local
  sssd:
    config_file_version: 2
    domains: example.com
    services: nss, sudo, pam, ssh
  nss:
    filter_groups: root
    filter_users: root
    homedir_substring: /home
  session_recording:
    scope: all
```

Testing
-------

[![Build Status](https://travis-ci.org/timorunge/ansible-sssd.svg?branch=master)](https://travis-ci.org/timorunge/ansible-sssd)

Dependencies
------------

None

License
-------
BSD

Author Information
------------------

- Timo Runge
