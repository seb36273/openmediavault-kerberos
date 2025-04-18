# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    Volker Theile <volker.theile@openmediavault.org>
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2009-2013 Volker Theile
# @copyright Copyright (c) 2013-2015 OpenMediaVault Plugin Developers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

{% set krb_config = salt['omv_conf.get']('conf.service.kerberos') %}
{% set ssh_config = salt['omv_conf.get']('conf.service.ssh') %}

{% if krb_config.enable | to_bool and krb_config.enablessh | to_bool and ssh_config.enable | to_bool %}

configure_ssh_sshd_config_kerberos:
  file.keyvalue:
    - name: /etc/ssh/sshd_config
    - key_values:
        KerberosAuthentication: 'yes'
        GSSAPIAuthentication: 'yes'
    - separator: ' '
    - uncomment: '# '
    - key_ignore_case: True
    - append_if_not_found: True
    - watch_in:
      - service: start_ssh_service

{% endif %}
