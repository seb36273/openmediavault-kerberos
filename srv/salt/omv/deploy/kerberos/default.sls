# This file is part of OpenMediaVault.
#
# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    Volker Theile <volker.theile@openmediavault.org>
# @copyright Copyright (c) 2009-2020 Volker Theile
#
# OpenMediaVault is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# OpenMediaVault is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenMediaVault. If not, see <http://www.gnu.org/licenses/>.

{% set config = salt['omv_conf.get']('conf.service.kerberos') %}

{% set krb5_config_file = salt['pillar.get']('default:OMV_KRB5_CONFIG', '/etc/krb5.conf') %}
{% set krb5_keytab_file = salt['pillar.get']('default:OMV_KRB5_KEYTAB', '/etc/krb5.keytab') %}

{% if config.enable | to_bool %}

configure_kerberos_config:
  file.managed:
    - name: {{ krb5_config_file }}
    - source:
      - salt://{{ tpldir }}/files/etc-krb5_conf.j2
    - template: jinja
    - context:
        config: {{ config | json }}
    - user: root
    - group: root
    - mode: 644

{% endif %}

configure_kerberos_keytab:
  file.managed:
    - name: {{ krb5_keytab_file }}
    - user: root
    - group: root
    - mode: 600
