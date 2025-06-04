# Kerberos Plugin for OpenMediaVault

This plugin implements a simple UI for configuring MIT Kerberos
for OpenMediaVault and integrating it with NFS and Samba.

Note that this is not intended to be a transparent plugin that integrates
Kerberos with the existing OpenMediaVault user/group/directory framework.
Rather, this provides an interface for the `/etc/krb5.conf` and
`/etc/krb5.keytab` files as well as NFS, Samba, and SSH integration.

Additionally, this only provides support for Kerberos *clients*. There is
no support for configuring and maintaining a KDC (although it does
have the capability to add keys to a KDC).

It supports the following:

- Configuring the local Kerberos client.
- Enabling Kerberos in NFS, Samba, SSH, and PAM.
- Listing the contents of the local keytab.
- Removing individual keys from the keytab.
- Loading keys from the configured KDC into the local keytab.
- Creating a new key on the KDC and loading it into the local keytab.

There are a few important caveats:

1. In terms of NFS, it automatically sets up all exported shares with the
   `sec` option set to `krb5:krb5i:krb5p`. This means that any of those are
   supported per share and it's up to the clients to pick one. It also
   means all shares require Kerberos.
2. The locations of the Kerberos config files and keytab are hardcoded.
3. Creating a new key assumes you also want to load it to the local keytab,
   there is no way to create a key on the KDC and *not* load it except to
   create it first, then remove it. That seems a bit silly and isn't the
   intent of this plugin.

**Be aware**: This code was tested in a clean environment with fresh installed OpenMediaVault setup.
I am not responsible for loss of your data! Please make always a full backup
of your OpenMediaVault machine before installing this plugin!

## Build DEBIAN Package

Create DEB package with `dpkg-buildpackage -uc -us` inside the
source directory. The \*.deb file will be placed in the parent
directory.

## Install Plugin into Openmediavault

Upload the generated \*.deb file to OpenMediaVault plugins and install it. Once it is
installed, you have an additional menu item for Kerberos under Access Rights Management.

## Environment for Testing

* Openmediavault 7.7.1-3 (Sandworm)

## Troubleshooting

If you get in trouble, try:
* check log files
* run `/usr/sbin/omv-engined --debug --foreground`
* check config with `omv-confdbadm read conf.service.kerberos`
* apply config with `omv-salt deploy run kerberos`
* remove all uploaded packages via `omv-firstaid` tool
* remove plugin and reinstall

## References
* [1]  https://github.com/openmediavault
* [2]  https://github.com/ikogan/openmediavault-kerberos
