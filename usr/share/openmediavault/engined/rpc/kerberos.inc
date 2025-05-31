<?php

/**
 * Copyright (C) 2009-2013 Volker Theile <volker.theile@openmediavault.org>
 * Copyright (C) 2013-2015 OpenMediaVault Plugin Developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

class OMVRpcServiceKerberos extends \OMV\Rpc\ServiceAbstract {
	/**
	 * Get the RPC service name.
	 */
	public function getName() {
		return "Kerberos";
	}

	/**
	 * Initialize the RPC service.
	 */
	public function initialize() {
		$this -> registerMethod("getSettings");
		$this -> registerMethod("setSettings");
		$this -> registerMethod("getKeyTab");
		$this -> registerMethod("addKey");
		$this -> registerMethod("removeKey");
		$this -> registerMethod("createKey");
	}

	/**
	 * Get the Kerberos configuration settings.
	 * @param params The method params
	 * @param context The context of the caller.
	 * @return A JSON object containing the fields required
	 *	to configure Kerberos.
	 */
	function getSettings($params, $context) {
		// Validate the RPC caller context.
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Get the configuration object.
		$db = \OMV\Config\Database::getInstance();
		return $db->getAssoc("conf.service.kerberos");
	}

	/**
	 * Set the Kerberos configuration settings.
	 * @param params An array containing all of the fields and values.
	 * @param context The context of the caller.
	 * @return The stored configuration object.
	 */
	function setSettings($params, $context) {
		// Validate the RPC caller context.
		$this->validateMethodContext($context, [
			"role" => OMV_ROLE_ADMINISTRATOR
		]);

		// Validate the parameters of the RPC service method.
		$this->validateMethodParams($params, "rpc.kerberos.setsettings");

		// Prepare the configuration object.
		$object = new \OMV\Config\ConfigObject("conf.service.kerberos");
		$object->setAssoc($params);

		// Set the configuration object.
		$db = \OMV\Config\Database::getInstance();
		$db->set($object);

		// Return the configuration object.
		return $object->getAssoc();
	}

	/**
	 * Get the current keytab.
	 *
	 * @param params An array containing all of the parameters to this function.
	 * @param context The context of the caller.
	 * @return A list of keytab items.
	 */
	function getKeyTab($params, $context) {
		// Validate the RPC caller context
		$this->validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Use klist -k to retrieve the all keytab entries (-e show encryption information)
		$cmd = sprintf("export LANG=C; klist -k /etc/krb5.keytab 2>&1");
		if (0 !== ($exitStatus = $this->exec($cmd, $output))) {
			throw new \OMV\ExecException($cmd, $output, $exitStatus);
		}

		$list = array();
		$uniqueEntries = array(); // Array to track unique entries

		foreach ($output as $outputv) {
			$outputv = preg_split("/\s+/", trim($outputv));

			// Ignore lines that do not start with a number
			if (isset($outputv[0]) && is_numeric($outputv[0])) {
				$kvno = intval($outputv[0]); // Key Version Number
				$principal = $outputv[1]; // Principal

				// Check if the entry already exists
				$entryKey = $kvno . ':' . $principal; // Unique key for kvno and Principal
				if (!isset($uniqueEntries[$entryKey])) {
					$uniqueEntries[$entryKey] = true; // Mark entry as unique

					$entry = array(
						"version" => $kvno,
						"principal" => $principal
					);

					$list[] = $entry;
				}
			}
		}

		return $list;
	}

	/**
	 * Load a key from a KDC into the local keytab.
	 *
	 * Required parameters are an admin principal that has rights
	 * to read the desired keytab, the admin principal's password,
	 * and the target keytab to load.
	 *
	 * @param params An array containing all of the parameters to this function.
	 * @param context The context of the caller.
	 * @return The output from kadmin.
	 */
	function addKey($params, $context) {
		// Validate the RPC caller context
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Validate the parameters of the RPC servicemethod.
		$this -> validateMethodParams($params, 'rpc.kerberos.principal.add');

		// Since kadmin's status reporting is rediculous, we're going
		// to see if this worked by reading the keytab before and after,
		// and comparing.
		$currentKeytab = $this -> getKeyTab($params, $context);

		$cmd = sprintf("export LANG=C; kadmin.local -q \"ktadd %s\" 2>&1",
				$params['principal']
		);
		$result = $this -> exec($cmd, $output);

		if($result !== 0) {
			throw new \OMV\Exception("Failed to add principal: %s", 
				implode("\n", $output)
			);
		}

		$newKeyTab = $this -> getKeyTab($params, $context);

		// If the number of keys in the old and new keytabs is identical, we failed.
		if(count($currentKeyTab) === count($newKeyTab)) {
			throw new \OMV\Exception("Failed to add principal");
		}

		return $output;
	}

	/**
	 * Remove one or more keys from the local keytab.
	 *
	 * This simply takes a list of slot numbers.
	 *
	 * @param params An array containing all of the parameters to this function.
	 * @param context The context of the caller.
	 * @return The output from ktutil.
	 */
	function removeKey($params, $context) {
		// Validate the RPC caller context
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Validate the parameters of the RPC servicemethod.
		$this -> validateMethodParams($params, 'rpc.kerberos.principal.remove');

		// Since kadmin's status reporting is rediculous, we're going
		// to see if this worked by reading the keytab before and after,
		// and comparing.
		$currentKeytab = $this -> getKeyTab($params, $context);

		$cmd = sprintf("export LANG=C; kadmin.local -q \"ktremove -k /etc/krb5.keytab %s %s\" 2>&1",
				$params['principal'],
				$params['version']
		);
		$result = $this -> exec($cmd, $output);

		if($result !== 0) {
			throw new \OMV\Exception("Failed to remove principal: %s", 
				implode("\n", $output)
			);
		}

		$newKeyTab = $this -> getKeyTab($params, $context);

		// If the number of keys in the old and new keytabs is identical, we failed.
		if(count($currentKeyTab) === count($newKeyTab)) {
			throw new \OMV\Exception("Failed to remove principal");
		}

		return $output;
	}

	/**
	 * Create a new key on the KDC and load it into the local keytab.
	 *
	 * Required parameters are an admin principal that has rights
	 * to read the desired keytab, the admin principal's password,
	 * the new principal to create, and either a password for the key
	 * or instructions to randomly generate a key.
	 *
	 * @param params An array containing all of the parameters to this function.
	 * @param context The context of the caller.
	 * @return The output from kadmin.
	 */
	function createKey($params, $context) {
		// Validate the RPC caller context
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Validate the parameters of the RPC servicemethod.
		$this -> validateMethodParams($params, 'rpc.kerberos.principal.create');

		// First, create the key on the key server. Order of the query matters,
		// so this is a bit weird.
		$cmd = sprintf("export LANG=C; kadmin.local -q \"addprinc");

		if($params['randomKey'] === TRUE) {
			$cmd .= " -randkey";
		} else {
			$cmd .= " -pw \\\"" . $params['newPrincipalKey'] . "\\\"";
		}

		$cmd .= " \\\"" . $params['newPrincipal'] . "\\\"\" 2>&1";

		$result = $this -> exec($cmd, $output);

		if($result !== 0) {
			throw new \OMV\Exception("Failed to create new key on KDC: %s", 
				implode("\n", $output)
			);
		}

		// Now, use addKey to add the key to the keytab.
		$params = array(
			"principal" => $params['newPrincipal']
		);
		$output .= $this -> addKey($params, $context);

		return $output;
	}
}
