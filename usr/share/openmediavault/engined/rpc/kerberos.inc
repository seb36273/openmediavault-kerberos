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
		$this -> registerMethod("addKeyFromKeyServer");
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
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		$cmd = sprintf("export LANG=C; echo \"rkt /etc/krb5.keytab\nlist\" | ktutil 2>&1");
		if (0 !== ($exitStatus = $this->exec($cmd, $output))) {
				throw new \OMV\ExecException($cmd, $output, $exitStatus);
		}

		$list = array();

		foreach($output as $outputv) {
			$outputv = preg_split("/\s+/", trim($outputv));

			// We need to throw away all of the lines that don't start with a number
			if(is_numeric($outputv[0])) {
				$entry = array(
					"slot" => intval($outputv[0]),
					"version" => intval($outputv[1]),
					"principal" => $outputv[2]
				);

				$regex = "/(.*)\/(.*)@(.*)$/";
				if(preg_match($this -> regex, $principal, $matches)) {
					$entry["type"] = $matches[1];
					$entry["object"] = $matches[2];
					$entry["realm"] = $matches[3];
				}

				$list[] = $entry;
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
	function addKeyFromKeyServer($params, $context) {
		// Validate the RPC caller context
		$this -> validateMethodContext($context, array(
			"role" => OMV_ROLE_ADMINISTRATOR
		));

		// Validate the parameters of the RPC servicemethod.
		$this -> validateMethodParams($params, '{
			"type": "object",
			"properties": {
				"adminPassword": {"type": "string"},
				"adminPrincipal": {"type": "string"},
				"targetPrincipal": {"type": "string"}
			}
		}');

		// Since kadmin's status reporting is rediculous, we're going
		// to see if this worked by reading the keytab before and after,
		// and comparing.
		$currentKeytab = $this -> getKeyTab($params, $context);

		$cmd = sprintf("export LANG=C; kadmin -p \"%s\" -w \"%s\" -q \"ktadd \\\"%s\\\"\" 2>&1",
				$params['adminPrincipal'],
				$params['adminPassword'],
				$params['targetPrincipal']
		);
		$result = $this -> exec($cmd, $output);

		if($result !== 0) {
			throw new \OMV\Exception("Failed to add desired key from KDC: %s", 
				implode("\n", $output)
			);
		}

		$newKeyTab = $this -> getKeyTab($params, $context);

		// If the number of keys in the old and new keytabs is identical, we failed.
		if(count($currentKeyTab) === count($newKeyTab)) {
			throw new \OMV\Exception("Failed to add desired key from KDC");
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
		$this -> validateMethodParams($params, '{
			"type": "object",
			"properties": {
				"slots": {
					"type": "array",
					"minItems": 1,
					"items": {
						"type": "integer"
					},
					"uniqueItems": true
				}
			}
		}');

		// ktutil is also rediculous. The slot number is monotonically
		// increasing, with no gaps. As soon as we remove a key, all keys
		// move down a slot. This means we can't actually use the slot number
		// as given to remove keys. We need to compute the correct slot number
		// to use based on the changes we're making. It's so much fun.
		//
		// However, if this operating will result in no keys, ktutil will simply
		// write no file. So, if there is only one key in the keytab or we're removing
		// the same number as in the keytab, simply delete the keytab file.
		$currentKeyTab = $this -> getKeyTab($params, $context);

		if(count($params['slots']) === count($currentKeyTab)) {
			$cmd = "export LANG=C; rm -f /etc/krb5.keytab";
		} else {
			arsort($params['slots']);

			$cmd = "export LANG=C; echo \"rkt /etc/krb5.keytab\n";

			// So, lets do this N times, one for each slot to be removed.
			// As we do this, every time we remove one, we decrement the rest
			// of the slots by 1.
			for($slot = 0; $slot < count($params['slots']); ++$slot) {
				$cmd .= "delent " . $params['slots'][$slot] . "\n";

				for($num = $slot+1; $num < count($params['slots']); ++$num) {
					$params['slots'][$num]--;
				}
			}

			$cmd .= "wkt /tmp/krb5.keytab\" | ktutil && mv /tmp/krb5.keytab /etc/krb5.keytab 2>&1";
		}

		$result = $this -> exec($cmd, $output);

		if($result !== 0) {
			throw new \OMV\Exception("Failed to remove key(s) from key tab: %s", 
				implode("\n", $output)
			);
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
		$this -> validateMethodParams($params, '{
			"type": "object",
			"properties": {
				"adminPassword": {"type": "string"},
				"adminPrincipal": {"type": "string"},
				"newPrincipal": {"type": "string"},
				"newPrincipalKey": {"type": "string", "optional": true},
				"randomKey": {"type": "boolean"}
			}
		}');

		// First, create the key on the key server. Order of the query matters,
		// so this is a bit weird.
		$cmd = sprintf("export LANG=C; kadmin -p \"%s\" -w \"%s\" -q \"addprinc",
				$params['adminPrincipal'],
				$params['adminPassword']
		);

		if($params['randomKey']) {
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

		// Now, use addKeyFromKeyServer to add the key to the keytab.
		$addParams = array(
			"adminPassword" => $params['adminPassword'],
			"adminPrincipal" => $params['adminPrincipal'],
			"targetPrincipal" => $params['newPrincipal']
		);

		$output .= $this -> addKeyFromKeyServer($addParams, $context);

		return $output;
	}
}
