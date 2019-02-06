# sssd

This role is installing and configuring the
[SSSD](https://github.com/SSSD/sssd) service.

It's also providing the possibility to install and patch a custom SSSD
version (from sources) according to your needs.

## Requirements

This role requires
[Ansible 2.6.0](https://docs.ansible.com/ansible/devel/roadmap/ROADMAP_2_6.html)
or higher in order to apply [patches](#3-apply-patches-to-the-source).

You can simply use pip to install (and define) a stable version:

```sh
pip install ansible==2.7.6
```

All platform requirements are listed in the metadata file.

## Install

- Use [tag 0.4.2](https://github.com/timorunge/ansible-sssd/releases/tag/0.4.2)
  for [SSSD >= 1.6.0](https://docs.pagure.org/SSSD.sssd/users/relnotes/notes_1_16_3.html)
- Use [tag >= 0.5.0](https://github.com/timorunge/ansible-sssd/releases/tag/0.5.0)
  for [SSSD >= 2.0.0](https://docs.pagure.org/SSSD.sssd/users/relnotes/notes_2_0_0.html)

### Recommendation

Stay with SSSD 1.6.x. The 2.0.0 release is working but I had to add some
[patches](files/patches/2.0.0) to get it up and running. The patches are
basically commits after the initial release.
The master is backwards compatible with the 1.6.13 release. 2.0.0 has just
more dependencies on Debian based systems (`gir1.2-glib-2.0,
libgirepository-1.0-1 & python-gi`, pip: `pyasn1, pyasn1-modules`).

```sh
ansible-galaxy install timorunge.sssd[,version]
```

#### Note for RedHat

Some of the packages that this role installs are only available in the
`rhel-6-server-optional-rpms` or `rhel-7-server-optional-rpms` repositories,
you might need to enable these repositories if you get an error like
"No package matching 'sssd-dbus' found available, installed or updated".

Enable this optional repo for RHEL 6:

```sh
subscription-manager repos --enable rhel-6-server-optional-rpms
```

And for RHEL 7:

```sh
subscription-manager repos --enable rhel-7-server-optional-rpms
```

## Role Variables

This role is basically building out of a YAML hierarchy an working
configuration file for the SSSD service.

The variables that can be passed to this role. You can find a brief
description in this paragraph. For all variables, take a look at the
[SSSD config options](#sssd-config-options).

```yaml
# Enable / disable SSSD as a service
# Type: Bool
sssd_service_enabled: yes

# Choose the config type: config (`sssd_config`), file (`sssd_config_src_file`)
# or none (disable sssd.conf generation)
# Type: Str
sssd_config_type: config

# Default SSSD config options
# Type: Dict
sssd_config:
  "domain/example.com":
    access_provider: permit
    auth_provider: local
    id_provider: local
  sssd:
    config_file_version: 2
    services: nss, pam
    domains: example.com

# Default SSSD config from file
# Type: Str
sssd_config_src_file: sssd.example.conf

# SSSD from source:

# Install SSSD from sources:
# Type: Bool
sssd_from_sources: False

# Version definition (just relevant if `sssd_from_sources` is True):
# Type: Str
sssd_version: 2.0.0

# Patches

# In this section you can apply custom patches to SSSD.
# You can find one example in the README.md and in the tests directory.
# Type: Dict
sssd_patches:
  fix-makefile:
    dest_file: Makefile.am
    patch_file: "files/patches/{{ sssd_version }}/fix-makefile.diff"
    state: present

# Build options

# The default build options are stored in `vars/{{ ansible_os_family }}.yml`
# Type: List
sssd_build_options: "{{ sssd_default_build_options }}"
```

## Examples

To keep the document lean the compile options are stripped.
You can find the SSSD build options in [this document](#sssd-build-options).

### 1) Configure SSSD according to your needs

```yaml
- hosts: all
  vars:
    sssd_config:
      "domain/example.com":
        access_provider: permit
        auth_provider: local
        id_provider: local
      sssd:
        config_file_version: 2
        domains: example.com
        services: nss, pam
  roles:
    - timorunge.sssd
```

### 2) Example SSSD configurationn for FreeIPA

```yaml
- hosts: all
  vars:
    sssd_config:
      "domain/example.com":
        access_provider: ipa
        auth_provider: ipa
        cache_credentials: True
        chpass_provider: ipa
        id_provider: ipa
        ipa_domain: example.com
        ipa_hostname: debian-eeBahPh3.example.com
        ipa_server: ipa-srv1.example.com
        krb5_store_password_if_offline: True
        ldap_tls_cacert: /etc/ipa/ca.crt
      sssd:
        config_file_version: 2
        domains: example.com
        services: ifp, nss, pam, ssh, sudo
      nss:
        homedir_substring: /home
        memcache_timeout: 600
  roles:
    - timorunge.sssd
```

### 3) Build and configure SSSD according to your needs

Beside the standard installation via packages it's also possible to build
SSSD from sources (in this example for Debian based systems).

```yaml
- hosts: all
  vars:
    sssd_from_sources: True
    sssd_version: 2.0.0
    sssd_default_build_options:
      - "--datadir=/usr/share"
      - "--disable-rpath"
      - "--disable-silent-rules"
      - "--disable-static"
      - "--enable-krb5-locator-plugin"
      - "--enable-nsslibdir=/lib/{{ sssd_dpkg_architecture }}"
      - "--enable-pac-responder"
      - "--enable-pammoddir=/lib/{{ sssd_dpkg_architecture }}/security"
      - "--enable-systemtap"
      - "--includedir=/usr/include"
      - "--infodir=/usr/local/share/info"
      - "--libdir=/usr/lib/{{ sssd_dpkg_architecture }}"
      - "--libexecdir=/usr/lib/{{ sssd_dpkg_architecture }}"
      - "--localstatedir=/var"
      - "--mandir=/usr/local/share/man"
      - "--prefix=/usr"
      - "--sysconfdir=/etc"
      - "--with-autofs"
      - "--with-environment-file={{ sssd_environment_file }}"
      - "--with-initscript=systemd"
      - "--with-krb5-conf=/etc/krb5.conf"
      - "--with-krb5-plugin-path=/usr/lib/{{ sssd_dpkg_architecture }}/krb5/plugins/libkrb5"
      - "--with-ldb-lib-dir=/usr/lib/{{ sssd_dpkg_architecture }}/ldb/modules/ldb"
      - "--with-log-path=/var/log/sssd"
      - "--with-pid-path=/var/run"
      - "--with-plugin-path=/usr/lib/{{ sssd_dpkg_architecture }}/sssd"
      - "--with-samba"
      - "--with-secrets-db-path=/var/lib/sss/secrets"
      - "--with-secrets"
      - "--with-ssh"
      - "--with-sudo-lib-path=/usr/lib/{{ sssd_dpkg_architecture }}"
      - "--with-sudo"
      - "--with-systemdunitdir=/lib/systemd/system"
    sssd_config:
      "domain/example.com":
        access_provider: permit
        auth_provider: local
        id_provider: local
      sssd:
        config_file_version: 2
        domains: example.com
        services: nss, pam
  roles:
    - timorunge.sssd
```

### 4) Don't generate any configuration

Useful if you're using this role in combination with e.g. the
[FreeIPA server](https://github.com/timorunge/ansible-freeipa-server)
or the [FreeIPA client](https://github.com/timorunge/ansible-freeipa-server).

```yaml
- hosts: all
  vars:
    sssd_config_type: none
    sssd_from_sources: True
    sssd_version: 2.0.0
  roles:
    - timorunge.sssd
```

### 5) Apply patches to the source

```yaml
- hosts: all
  vars:
    sssd_from_sources: True
    sssd_version: 2.0.0
    sssd_patches:
      fix-makefile:
        dest_file: Makefile.am
        patch_file: "files/patches/{{ sssd_version }}/fix-makefile.diff"
        state: present
    sssd_build_options: "{{ sssd_default_build_options }}"
    sssd_config:
      "domain/example.com":
        access_provider: permit
        auth_provider: local
        id_provider: local
      sssd:
        config_file_version: 2
        domains: example.com
        services: nss, pam
  roles:
    - timorunge.sssd
```

### 6) Override init.d and systemd templates

```yaml
- hosts: all
  vars:
    sssd_init_template: roles/sssd/templates/sssd.service.j2
    sssd_service_template: roles/sssd/templates/sssd.init.j2
    sssd_config:
      "domain/example.com":
        access_provider: permit
        auth_provider: local
        id_provider: local
      sssd:
        config_file_version: 2
        domains: example.com
        services: nss, pam
  roles:
    - timorunge.sssd
```

## SSSD config options

```yaml
# Format:
# option: type, subtype, mandatory[, default]
sssd_config:
  service:
    # Options available to all services
    timeout: int, None, false
    debug: int, None, false
    debug_level: int, None, false
    debug_timestamps: bool, None, false
    debug_microseconds: bool, None, false
    debug_to_files: bool, None, false
    command: str, None, false
    reconnection_retries: int, None, false
    fd_limit: int, None, false
    client_idle_timeout: int, None, false
    responder_idle_timeout: int, None, false
    cache_first: int, None, false
    description: str, None, false

  sssd:
    # Monitor service
    config_file_version: int, None, false
    services: list, str, true, nss, pam
    domains: list, str, true
    sbus_timeout: int, None, false
    re_expression: str, None, false
    full_name_format: str, None, false
    krb5_rcache_dir: str, None, false
    user: str, None, false
    default_domain_suffix: str, None, false
    certificate_verification: str, None, false
    override_space: str, None, false
    disable_netlink: bool, None, false
    enable_files_domain: str, None, false
    domain_resolution_order: list, str, false
    try_inotify: bool, None, false

  nss:
    # Name service
    enum_cache_timeout: int, None, false
    entry_cache_nowait_percentage: int, None, false
    entry_negative_timeout: int, None, false
    local_negative_timeout: int, None, false
    filter_users: list, str, false
    filter_groups: list, str, false
    filter_users_in_groups: bool, None, false
    pwfield: str, None, false
    override_homedir: str, None, false
    fallback_homedir: str, None, false
    homedir_substring: str, None, false, /home
    override_shell: str, None, false
    allowed_shells: list, str, false
    vetoed_shells: list, str, false
    shell_fallback: str, None, false
    default_shell: str, None, false
    get_domains_timeout: int, None, false
    memcache_timeout: int, None, false
    user_attributes: str, None, false

  pam:
    # Authentication service
    offline_credentials_expiration: int, None, false
    offline_failed_login_attempts: int, None, false
    offline_failed_login_delay: int, None, false
    pam_verbosity: int, None, false
    pam_response_filter: str, None, false
    pam_id_timeout: int, None, false
    pam_pwd_expiration_warning: int, None, false
    get_domains_timeout: int, None, false
    pam_trusted_users: str, None, false
    pam_public_domains: str, None, false
    pam_account_expired_message: str, None, false
    pam_account_locked_message: str, None, false
    pam_cert_auth: bool, None, false
    pam_cert_db_path: str, None, false
    p11_child_timeout: int, None, false
    pam_app_services: str, None, false
    pam_p11_allowed_services: str, None, false

  sudo:
    # sudo service
    sudo_timed: bool, None, false
    sudo_inverse_order: bool, None, false
    sudo_threshold: int, None, false

  autofs:
    # autofs service
    autofs_negative_timeout: int, None, false

  ssh:
    # ssh service
    ssh_hash_known_hosts: bool, None, false
    ssh_known_hosts_timeout: int, None, false
    ca_db: str, None, false

  pac:
    # PAC responder
    allowed_uids: str, None, false
    pac_lifetime: int, None, false

  ifp:
    # InfoPipe responder
    allowed_uids: str, None, false
    user_attributes: str, None, false

  secrets:
    # Secrets service
    provider: str, None, false
    containers_nest_level: int, None, false
    max_secrets: int, None, false
    max_uid_secrets: int, None, false
    max_payload_size: int, None, false
    # Secrets service - proxy
    proxy_url: str, None, false
    auth_type: str, None, false
    auth_header_name: str, None, false
    auth_header_value: str, None, false
    forward_headers: list, None, false
    username: str, None, false
    password: str, None, false
    verify_peer: bool, None, false
    verify_host: bool, None, false
    capath: str, None, false
    cacert: str, None, false
    cert: str, None, false
    key: str, None, false

  session_recording:
    # Session recording service
    scope: str, None, false
    users: list, str, false
    groups: list, str, false

  provider:
    # Available provider types
    id_provider: str, None, true
    auth_provider: str, None, false
    access_provider: str, None, false
    chpass_provider: str, None, false
    sudo_provider: str, None, false
    autofs_provider: str, None, false
    hostid_provider: str, None, false
    subdomains_provider: str, None, false
    selinux_provider: str, None, false
    session_provider: str, None, false

  domain:
    # Options available to all domains
    description: str, None, false
    domain_type: str, None, false
    debug: int, None, false
    debug_level: int, None, false
    debug_timestamps: bool, None, false
    command: str, None, false
    min_id: int, None, false
    max_id: int, None, false
    timeout: int, None, false
    enumerate: bool, None, false
    subdomain_enumerate: str, None, false
    offline_timeout: int, None, false
    cache_credentials: bool, None, false
    cache_credentials_minimal_first_factor_length: int, None, false
    use_fully_qualified_names: bool, None, false
    ignore_group_members: bool, None, false
    entry_cache_timeout: int, None, false
    lookup_family_order: str, None, false
    account_cache_expiration: int, None, false
    pwd_expiration_warning: int, None, false
    filter_users: list, str, false
    filter_groups: list, str, false
    dns_resolver_timeout: int, None, false
    dns_discovery_domain: str, None, false
    override_gid: int, None, false
    case_sensitive: str, None, false
    override_homedir: str, None, false
    fallback_homedir: str, None, false
    homedir_substring: str, None, false
    override_shell: str, None, false
    default_shell: str, None, false
    description: str, None, false
    realmd_tags: str, None, false
    subdomain_refresh_interval: int, None, false
    subdomain_inherit: str, None, false
    subdomain_homedir: str, None, false
    cached_auth_timeout: int, None, false
    full_name_format: str, None, false
    re_expression: str, None, false
    auto_private_groups: str, None, false

    # Entry cache timeouts
    entry_cache_user_timeout: int, None, false
    entry_cache_group_timeout: int, None, false
    entry_cache_netgroup_timeout: int, None, false
    entry_cache_service_timeout: int, None, false
    entry_cache_autofs_timeout: int, None, false
    entry_cache_sudo_timeout: int, None, false
    entry_cache_ssh_host_timeout: int, None, false
    refresh_expired_interval: int, None, false

    # Dynamic DNS updates
    dyndns_update: bool, None, false
    dyndns_ttl: int, None, false
    dyndns_iface: str, None, false
    dyndns_refresh_interval: int, None, false
    dyndns_update_ptr: bool, None, false
    dyndns_force_tcp: bool, None, false
    dyndns_auth: str, None, false
    dyndns_server: str, None, false

  # Special providers
  provider/permit:

  provider/permit/access:

  provider/deny:

  provider/deny/access:
```

## SSSD build options

An overview of the build options for SSSD (2.0.0).

```sh
`configure' configures sssd 2.0.0 to adapt to many kinds of systems.

Usage: ./configure [OPTION]... [VAR=VALUE]...

To assign environment variables (e.g., CC, CFLAGS...), specify them as
VAR=VALUE.  See below for descriptions of some of the useful variables.

Defaults for the options are specified in brackets.

Configuration:
  -h, --help              display this help and exit
      --help=short        display options specific to this package
      --help=recursive    display the short help of all the included packages
  -V, --version           display version information and exit
  -q, --quiet, --silent   do not print `checking ...' messages
      --cache-file=FILE   cache test results in FILE [disabled]
  -C, --config-cache      alias for `--cache-file=config.cache'
  -n, --no-create         do not create output files
      --srcdir=DIR        find the sources in DIR [configure dir or `..']

Installation directories:
  --prefix=PREFIX         install architecture-independent files in PREFIX
                          [/usr/local]
  --exec-prefix=EPREFIX   install architecture-dependent files in EPREFIX
                          [PREFIX]

By default, `make install' will install all the files in
`/usr/local/bin', `/usr/local/lib' etc.  You can specify
an installation prefix other than `/usr/local' using `--prefix',
for instance `--prefix=$HOME'.

For better control, use the options below.

Fine tuning of the installation directories:
  --bindir=DIR            user executables [EPREFIX/bin]
  --sbindir=DIR           system admin executables [EPREFIX/sbin]
  --libexecdir=DIR        program executables [EPREFIX/libexec]
  --sysconfdir=DIR        read-only single-machine data [PREFIX/etc]
  --sharedstatedir=DIR    modifiable architecture-independent data [PREFIX/com]
  --localstatedir=DIR     modifiable single-machine data [PREFIX/var]
  --libdir=DIR            object code libraries [EPREFIX/lib]
  --includedir=DIR        C header files [PREFIX/include]
  --oldincludedir=DIR     C header files for non-gcc [/usr/include]
  --datarootdir=DIR       read-only arch.-independent data root [PREFIX/share]
  --datadir=DIR           read-only architecture-independent data [DATAROOTDIR]
  --infodir=DIR           info documentation [DATAROOTDIR/info]
  --localedir=DIR         locale-dependent data [DATAROOTDIR/locale]
  --mandir=DIR            man documentation [DATAROOTDIR/man]
  --docdir=DIR            documentation root [DATAROOTDIR/doc/sssd]
  --htmldir=DIR           html documentation [DOCDIR]
  --dvidir=DIR            dvi documentation [DOCDIR]
  --pdfdir=DIR            pdf documentation [DOCDIR]
  --psdir=DIR             ps documentation [DOCDIR]

Program names:
  --program-prefix=PREFIX            prepend PREFIX to installed program names
  --program-suffix=SUFFIX            append SUFFIX to installed program names
  --program-transform-name=PROGRAM   run sed PROGRAM on installed program names

System types:
  --build=BUILD     configure for building on BUILD [guessed]
  --host=HOST       cross-compile to build programs to run on HOST [BUILD]

Optional Features:
  --disable-option-checking  ignore unrecognized --enable/--with options
  --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
  --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
  --enable-dependency-tracking
                          do not reject slow dependency extractors
  --disable-dependency-tracking
                          speeds up one-time build
  --enable-silent-rules   less verbose build output (undo: "make V=1")
  --disable-silent-rules  verbose build output (undo: "make V=0")
  --enable-static[=PKGS]  build static libraries [default=no]
  --enable-shared[=PKGS]  build shared libraries [default=yes]
  --enable-fast-install[=PKGS]
                          optimize for fast installation [default=yes]
  --disable-libtool-lock  avoid locking (might break parallel builds)
  --disable-nls           do not use Native Language Support
  --disable-rpath         do not hardcode runtime library paths
  --enable-nsslibdir      Where to install nss libraries ($libdir)
  --enable-pammoddir      Where to install pam modules ($libdir/security)
  --enable-nfsidmaplibdir Where to install libnfsidmap libraries
                          ($libdir/libnfsidmap)
  --enable-all-experimental-features
                          build all experimental features
  --enable-sss-default-nss-plugin
                          This option change standard behaviour of sss nss
                          plugin. If this option is enabled the sss nss plugin
                          will behave as it was not in nsswitch.conf when sssd
                          is not running. [default=no]
  --enable-files-domain   If this feature is enabled, then SSSD always enables
                          a domain with id_provider=files even if the domain
                          is not specified in the config file [default=no]
  --enable-local-provider If this feature is enabled, then local-provider will
                          be built by default. [default=no]
  --enable-ldb-version-check
                          compile with ldb runtime version check [default=no]
  --disable-krb5-locator-plugin
                          do not build Kerberos locator plugin
  --enable-pac-responder  build pac responder
  --disable-cifs-idmap-plugin
                          do not build CIFS idmap plugin
  --enable-systemtap      Enable inclusion of systemtap trace support
  --enable-intgcheck-reqs enable checking for integration test requirements
                          [default=no]
  --enable-polkit-rules-path=PATH
                          Path to store polkit rules at. Use --disable to not
                          install the rules at all.
                          [/usr/share/polkit-1/rules.d]


Optional Packages:
  --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
  --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
  --with-pic[=PKGS]       try to use only PIC/non-PIC objects [default=use
                          both]
  --with-gnu-ld           assume the C compiler uses GNU ld [default=no]
  --with-sysroot=DIR Search for dependent libraries within DIR
                        (or the compiler's sysroot if not specified).
  --with-gnu-ld           assume the C compiler uses GNU ld default=no
  --with-libiconv-prefix[=DIR]  search for libiconv in DIR/include and DIR/lib
  --without-libiconv-prefix     don't search for libiconv in includedir and libdir
  --with-libintl-prefix[=DIR]  search for libintl in DIR/include and DIR/lib
  --without-libintl-prefix     don't search for libintl in includedir and libdir
  --with-shared-build-dir=DIR
                          temporary build directory where libraries are
                          installed [$srcdir/sharedbuild]
  --with-os=OS_TYPE       Type of your operation system
                          (fedora|redhat|suse|gentoo)

  --with-db-path=PATH     Path to the SSSD databases [/var/lib/sss/db]


  --with-plugin-path=PATH Path to the SSSD data provider plugins
                          [/usr/lib/sssd]


  --with-pid-path=PATH    Where to store pid files for the SSSD [/var/run]


  --with-log-path=PATH    Where to store log files for the SSSD
                          [/var/log/sssd]


  --with-pubconf-path=PATH
                          Where to store pubconf files for the SSSD
                          [/var/lib/sss/pubconf]


  --with-pipe-path=PATH   Where to store pipe files for the SSSD interconnects
                          [/var/lib/sss/pipes]


  --with-mcache-path=PATH Where to store mmap cache files for the SSSD
                          interconnects [/var/lib/sss/mc]


  --with-default-ccache-dir=CCACHEDIR
                          The default value of krb5_ccachedir [/tmp]


  --with-default-ccname-template=CCACHE
                          The default fallback value of krb5_ccname_template
                          [FILE:%d/krb5cc_%U_XXXXXX]


  --with-environment-file=PATH
                          Path to environment file [/etc/sysconfig/sssd]


  --with-init-dir=DIR     Where to store init script for sssd
                          [/etc/rc.d/init.d]


  --with-test-dir=PATH    Directory used for make check temporary files
                          [$builddir]

  --with-manpages         Whether to regenerate man pages from DocBook sources
                          [yes]

  --with-xml-catalog-path=PATH
                          Where to look for XML catalog [/etc/xml/catalog]


  --with-krb5-plugin-path=PATH
                          Path to Kerberos plugin store
                          [/usr/lib/krb5/plugins/libkrb5]


  --with-krb5-rcache-dir=PATH
                          Path to store Kerberos replay caches
                          [__LIBKRB5_DEFAULTS__]


  --with-krb5authdata-plugin-path=PATH
                          Path to Kerberos authdata plugin store
                          [/usr/lib/krb5/plugins/authdata]


  --with-krb5-conf=PATH   Path to krb5.conf file [/etc/krb5.conf]


  --with-python2-bindings Whether to build python2 bindings [yes]

  --with-python3-bindings Whether to build python3 bindings [yes]

  --with-cifs-plugin-path=PATH
                          Path to cifs-utils plugin store
                          [/usr/lib/cifs-utils]


  --with-winbind-plugin-path=PATH
                          Path to winbind idmap plugin store
                          [/usr/lib/samba/idmap]


  --with-selinux          Whether to build with SELinux support [yes]

  --with-nscd=PATH        Path to nscd binary to attempt to flush nscd cache
                          after local domain operations [/usr/sbin/nscd]


  --with-ipa-getkeytab=PATH
                          Path to ipa_getkeytab binary to retrieve keytabs
                          from FreeIPA server [/usr/sbin/ipa-getkeytab]


  --with-semanage         Whether to build with SELinux user management
                          support [yes]

  --with-ad-gpo-default=enforcing|permissive
                          Default enforcing level for AD GPO access-control
                          (enforcing)


  --with-gpo-cache-path=PATH
                          Where to store GPO policy files
                          [/var/lib/sss/gpo_cache]


  --with-nologin-shell=PATH
                          The shell used to deny access to users
                          [/sbin/nologin]


  --with-session-recording-shell=PATH
                          The shell used to record user sessions
                          [/usr/bin/tlog-rec-session]


  --with-app-libs=<path>  Path to the 3rd party application plugins
                          [/usr/lib/sssd/modules]


  --with-sudo             Whether to build with sudo support [yes]

  --with-sudo-lib-path=<path>
                          Path to the sudo library [/usr/lib/]


  --with-autofs           Whether to build with autofs support [yes]

  --with-ssh              Whether to build with SSH support [yes]

  --with-infopipe         Whether to build with InfoPipe support [yes]

  --with-crypto=CRYPTO_LIB
                          The cryptographic library to use (nss|libcrypto).
                          The default is nss.

  --with-syslog=SYSLOG_TYPE
                          Type of your system logger (syslog|journald).
                          [syslog]

  --with-samba            Whether to build with samba4 libraries [yes]

  --with-nfsv4-idmapd-plugin
                          Whether to build with NFSv4 IDMAP support [yes]

  --with-nfs-lib-path=<path>
                          Path to the NFS library [${libdir}]


  --with-libwbclient      Whether to build SSSD implementation of libwbclient
                          [yes]

  --with-sssd-user=<user> User for running SSSD (root)


  --with-secrets          Whether to build with secrets support [no]

  --with-secrets-db-path=PATH
                          Path to the SSSD databases [/var/lib/sss/secrets]


  --with-kcm              Whether to build with KCM server support [yes]

  --with-ldb-lib-dir=PATH Path to store ldb modules [${libdir}/ldb]


  --with-smb-idmap-interface-version=5|6
                          Idmap interface version of installed Samba


  --with-unicode-lib=<library>
                          Which library to use for Unicode processing
                          (libunistring, glib2) [glib2]


  --with-libnl            Whether to build with libnetlink support (libnl3,
                          libnl1, no) [auto]

  --with-nscd-conf=PATH   Path to nscd.conf file [/etc/nscd.conf]


  --with-initscript=INITSCRIPT_TYPE
                          Type of your init script (sysv|systemd). [sysv]


   --with-systemdunitdir=DIR
                          Directory for systemd service files [Auto],

   --with-systemdconfdir=DIR
                          Directory for systemd service file overrides [Auto],

  --with-tapset-install-dir
                          The absolute path where the tapset dir will be
                          installed

Some influential environment variables:
  CC          C compiler command
  CFLAGS      C compiler flags
  LDFLAGS     linker flags, e.g. -L<lib dir> if you have libraries in a
              nonstandard directory <lib dir>
  LIBS        libraries to pass to the linker, e.g. -l<library>
  CPPFLAGS    (Objective) C/C++ preprocessor flags, e.g. -I<include dir> if
              you have headers in a nonstandard directory <include dir>
  CPP         C preprocessor
  PKG_CONFIG  path to pkg-config utility
  POPT_CFLAGS C compiler flags for POPT, overriding pkg-config
  POPT_LIBS   linker flags for POPT, overriding pkg-config
  TALLOC_CFLAGS
              C compiler flags for TALLOC, overriding pkg-config
  TALLOC_LIBS linker flags for TALLOC, overriding pkg-config
  TDB_CFLAGS  C compiler flags for TDB, overriding pkg-config
  TDB_LIBS    linker flags for TDB, overriding pkg-config
  TEVENT_CFLAGS
              C compiler flags for TEVENT, overriding pkg-config
  TEVENT_LIBS linker flags for TEVENT, overriding pkg-config
  LDB_CFLAGS  C compiler flags for LDB, overriding pkg-config
  LDB_LIBS    linker flags for LDB, overriding pkg-config
  DHASH_CFLAGS
              C compiler flags for DHASH, overriding pkg-config
  DHASH_LIBS  linker flags for DHASH, overriding pkg-config
  COLLECTION_CFLAGS
              C compiler flags for COLLECTION, overriding pkg-config
  COLLECTION_LIBS
              linker flags for COLLECTION, overriding pkg-config
  INI_CONFIG_V0_CFLAGS
              C compiler flags for INI_CONFIG_V0, overriding pkg-config
  INI_CONFIG_V0_LIBS
              linker flags for INI_CONFIG_V0, overriding pkg-config
  INI_CONFIG_V1_CFLAGS
              C compiler flags for INI_CONFIG_V1, overriding pkg-config
  INI_CONFIG_V1_LIBS
              linker flags for INI_CONFIG_V1, overriding pkg-config
  INI_CONFIG_V1_1_CFLAGS
              C compiler flags for INI_CONFIG_V1_1, overriding pkg-config
  INI_CONFIG_V1_1_LIBS
              linker flags for INI_CONFIG_V1_1, overriding pkg-config
  INI_CONFIG_V1_3_CFLAGS
              C compiler flags for INI_CONFIG_V1_3, overriding pkg-config
  INI_CONFIG_V1_3_LIBS
              linker flags for INI_CONFIG_V1_3, overriding pkg-config
  GDM_PAM_EXTENSIONS_CFLAGS
              C compiler flags for GDM_PAM_EXTENSIONS, overriding pkg-config
  GDM_PAM_EXTENSIONS_LIBS
              linker flags for GDM_PAM_EXTENSIONS, overriding pkg-config
  PCRE_CFLAGS C compiler flags for PCRE, overriding pkg-config
  PCRE_LIBS   linker flags for PCRE, overriding pkg-config
  KRB5_CFLAGS C compiler flags for kerberos, overriding krb5-config
  KRB5_LIBS   linker flags for kerberos, overriding krb5-config
  CARES_CFLAGS
              C compiler flags for CARES, overriding pkg-config
  CARES_LIBS  linker flags for CARES, overriding pkg-config
  SYSTEMD_LOGIN_CFLAGS
              C compiler flags for SYSTEMD_LOGIN, overriding pkg-config
  SYSTEMD_LOGIN_LIBS
              linker flags for SYSTEMD_LOGIN, overriding pkg-config
  SYSTEMD_DAEMON_CFLAGS
              C compiler flags for SYSTEMD_DAEMON, overriding pkg-config
  SYSTEMD_DAEMON_LIBS
              linker flags for SYSTEMD_DAEMON, overriding pkg-config
  NDR_NBT_CFLAGS
              C compiler flags for NDR_NBT, overriding pkg-config
  NDR_NBT_LIBS
              linker flags for NDR_NBT, overriding pkg-config
  NDR_KRB5PAC_CFLAGS
              C compiler flags for NDR_KRB5PAC, overriding pkg-config
  NDR_KRB5PAC_LIBS
              linker flags for NDR_KRB5PAC, overriding pkg-config
  SMBCLIENT_CFLAGS
              C compiler flags for SMBCLIENT, overriding pkg-config
  SMBCLIENT_LIBS
              linker flags for SMBCLIENT, overriding pkg-config
  SASL_CFLAGS C compiler flags for SASL, overriding pkg-config
  SASL_LIBS   linker flags for SASL, overriding pkg-config
  NFSIDMAP_CFLAGS
              C compiler flags for NFSIDMAP, overriding pkg-config
  NFSIDMAP_LIBS
              linker flags for NFSIDMAP, overriding pkg-config
  HTTP_PARSER_CFLAGS
              C compiler flags for HTTP_PARSER, overriding pkg-config
  HTTP_PARSER_LIBS
              linker flags for HTTP_PARSER, overriding pkg-config
  CURL_CFLAGS C compiler flags for CURL, overriding pkg-config
  CURL_LIBS   linker flags for CURL, overriding pkg-config
  UUID_CFLAGS C compiler flags for UUID, overriding pkg-config
  UUID_LIBS   linker flags for UUID, overriding pkg-config
  JANSSON_CFLAGS
              C compiler flags for JANSSON, overriding pkg-config
  JANSSON_LIBS
              linker flags for JANSSON, overriding pkg-config
  GLIB2_CFLAGS
              C compiler flags for GLIB2, overriding pkg-config
  GLIB2_LIBS  linker flags for GLIB2, overriding pkg-config
  LIBNL3_CFLAGS
              C compiler flags for LIBNL3, overriding pkg-config
  LIBNL3_LIBS linker flags for LIBNL3, overriding pkg-config
  LIBNL1_CFLAGS
              C compiler flags for LIBNL1, overriding pkg-config
  LIBNL1_LIBS linker flags for LIBNL1, overriding pkg-config
  DBUS_CFLAGS C compiler flags for DBUS, overriding pkg-config
  DBUS_LIBS   linker flags for DBUS, overriding pkg-config
  PYTHON      the Python interpreter
  JOURNALD_CFLAGS
              C compiler flags for JOURNALD, overriding pkg-config
  JOURNALD_LIBS
              linker flags for JOURNALD, overriding pkg-config
  NSS_CFLAGS  C compiler flags for NSS, overriding pkg-config
  NSS_LIBS    linker flags for NSS, overriding pkg-config
  CRYPTO_CFLAGS
              C compiler flags for CRYPTO, overriding pkg-config
  CRYPTO_LIBS linker flags for CRYPTO, overriding pkg-config
  SSL_CFLAGS  C compiler flags for SSL, overriding pkg-config
  SSL_LIBS    linker flags for SSL, overriding pkg-config
  P11_KIT_CFLAGS
              C compiler flags for P11_KIT, overriding pkg-config
  P11_KIT_LIBS
              linker flags for P11_KIT, overriding pkg-config
  CHECK_CFLAGS
              C compiler flags for CHECK, overriding pkg-config
  CHECK_LIBS  linker flags for CHECK, overriding pkg-config
  CMOCKA_CFLAGS
              C compiler flags for CMOCKA, overriding pkg-config
  CMOCKA_LIBS linker flags for CMOCKA, overriding pkg-config

Use these variables to override the choices made by `configure' or to help
it to find libraries and programs with nonstandard names/locations.

Report bugs to <sssd-devel@lists.fedorahosted.org>.
```

## Testing

[![Build Status](https://travis-ci.org/timorunge/ansible-sssd.svg?branch=master)](https://travis-ci.org/timorunge/ansible-sssd)

Tests are done with [Docker](https://www.docker.com) and
[docker_test_runner](https://github.com/timorunge/docker-test-runner) which
brings up the following containers with different environment settings:

- CentOS 7
- Debian 9.4 (Stretch)
- Debian 10 (Buster)
- Ubuntu 16.04 (Xenial Xerus)
- Ubuntu 17.10 (Artful Aardvark)
- Ubuntu 18.04 (Bionic Beaver)
- Ubuntu 18.10 (Cosmic Cuttlefish)

Ansible 2.7.6 is installed on all containers and a
[test playbook](tests/test.yml) is getting applied.

For further details and additional checks take a look at the
[docker_test_runner configuration](tests/docker_test_runner.yml) and the
[Docker entrypoint](tests/docker/docker-entrypoint.sh).

```sh
# Testing locally:
curl https://raw.githubusercontent.com/timorunge/docker-test-runner/master/install.sh | sh
./docker_test_runner.py -f tests/docker_test_runner.yml
```

Since the build time on Travis is limited for public repositories the
automated tests are limited to:

- CentOS 7
- Debian 9.4 (Stretch)
- Ubuntu 18.04 (Bionic Beaver)

## Dependencies

### Ubuntu 16.04

On Ubuntu 16.04 you have to ensure that `pyopenssl` is
[up to date](docker/Dockerfile_Ubuntu_16_04#L18) before the
installation of SSSD.

```sh
pip install --upgrade pyopenssl
```

## License

[BSD 3-Clause "New" or "Revised" License](https://spdx.org/licenses/BSD-3-Clause.html)

## Author Information

- Timo Runge
