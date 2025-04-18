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

{% set krb_config = salt['omv_conf.get']('conf.service.kerberos') %}
{% set nfs_config = salt['omv_conf.get']('conf.service.nfs') %}

{% if krb_config.enable | to_bool %}

{% if krb_config.enablenfs | to_bool and nfs_config.enable | to_bool %}

include:
  - omv.deploy.nfs

extend:
  configure_nfsd_exports:
    file.managed:
      - source: salt://{{ tpldir }}/files/etc-exports.j2

{% endif %}

configure_kerberos_config:
  file.managed:
    - name: /etc/krb5.conf
    - source:
      - salt://{{ tpldir }}/files/etc-krb5_conf.j2
    - template: jinja
    - context:
        config: {{ krb_config | json }}
    - user: root
    - group: root
    - mode: 644

{% endif %}
