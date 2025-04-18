#!/bin/sh
#
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

set -e

. /usr/share/openmediavault/scripts/helper-functions

########################################################################
# Update the configuration.
# <config>
#   <services>
#     <kerberos>
#       <enable>0</enable>
#       <realm></realm>
#       <kdcs></kdcs>
#       <adminserver></adminserver>
#       <enablenfs>0</enablenfs>
#       <enablesmb>0</enablesmb>
#       <enablessh>0</enablessh>
#       <enablepam>0</enablepam>
#       <extraoptions></extraoptions>
#       <logging>1</logging>
#     </kerberos>
#   </services>
# </config>
########################################################################
if ! omv_config_exists "/config/services/kerberos"; then
	omv_config_add_node "/config/services" "kerberos"
	omv_config_add_key "/config/services/kerberos" "enable" "0"
	omv_config_add_key "/config/services/kerberos" "realm" ""
	omv_config_add_key "/config/services/kerberos" "kdcs" ""
	omv_config_add_key "/config/services/kerberos" "adminserver" ""
	omv_config_add_key "/config/services/kerberos" "enablenfs" "0"
	omv_config_add_key "/config/services/kerberos" "enablesmb" "0"
	omv_config_add_key "/config/services/kerberos" "enablessh" "0"
	omv_config_add_key "/config/services/kerberos" "enablepam" "0"
	omv_config_add_key "/config/services/kerberos" "extraoptions" ""
	omv_config_add_key "/config/services/kerberos" "logging" "1"
fi

exit 0
