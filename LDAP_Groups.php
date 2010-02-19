<?php

if (!defined( 'MEDIAWIKI' )) {
	die('This file is a MediaWiki extension, it is not a valid entry point');
}

$wgExtensionCredits['other'][] = array(
	'name' => "LDAP_Groups",
	'description' => "Allows pulling groups from multiple LDAP based on REMOTE_USER and REMOTE_REALM",
	'version' => "1.0",
	'author' => "Andy Cobaugh (phalenor@bx.psu.edu)",
	'url' => "http://github.com/phalenor/mw-ldap_groups"
);

/* Function used as the UserEffectiveGroups hook
 *
 * accepts: $user object and existing groups
 * returns: array of groups
 */
function efLDAP_Groups($user, $mw_groups) {
	global $realm_to_ldap, $_SERVER, $ldap_groups_always_search, $ldap_groups_enumerate_realm_server;

	$uid = $user->mName;
	$mId = $user->mId;

	$groups = array();

	/* if we're authenticating, get groups from ldap */
	if (stripos($_SERVER['SCRIPT_NAME'], 'auth.php')) {
		/* if server config exists for REMOTE_REALM and we want to enumerate over it */
		if (array_key_exists($_SERVER['REMOTE_REALM'], $realm_to_ldap) && $ldap_groups_enumerate_realm_server === TRUE) {
			$ldap_server = $realm_to_ldap[$_SERVER['REMOTE_REALM']];
			$groups = array_merge($groups, efLDAP_Groups_enumerate_from_ldap($ldap_server, $uid));
		}
		/* if there is a realm that we always want to enumerate groups from */
		if (array_key_exists($ldap_groups_always_search, $realm_to_ldap) 
			&& ($ldap_groups_always_search != $_SERVER['REMOTE_REALM'] || $ldap_groups_enumerate_realm_server === FALSE)) {
			$ldap_server = $realm_to_ldap[$ldap_groups_always_search];
			$groups = array_merge($groups, efLDAP_Groups_enumerate_from_ldap($ldap_server, $uid));
		}
		# add the implicit group for this realm
		if (array_key_exists($_SERVER['REMOTE_REALM'], $realm_to_ldap)) {
			$groups = array_merge($groups, array($realm_to_ldap[$_SERVER['REMOTE_REALM']]['implicit_group_name']));
		}
		/* now cache for future use */
		efLDAP_Groups_write_cache($mId, $groups);
	} else { /* else, get the groups from the cache */
		$groups = efLDAP_Groups_enumerate_from_cache($mId);
	}

	/* merge our groups with existing mediawiki groups */
	$mw_groups = array_merge($groups, $mw_groups);

	return true;
}

/* Searches and returns groups from ldap server
 *
 * accepts: $ldap_server as the definition of the ldap server to 
 *          connect to with all its settings, $uid is the uid to 
 *          search for
 * returns: array of ldap groups
 */
function efLDAP_Groups_enumerate_from_ldap($ldap_server, $uid) {
	global $ldap_groups_strip_realm;

	extract($ldap_server, EXTR_PREFIX_ALL, 'ldap');
	
	$ldapconn = ldap_connect($ldap_hostname) or error_log("Could not connect to ldap server.");
	$ldapbind = ldap_bind($ldapconn) or error_log("Could not bind to ldap server $ldap_hostname.");

	/* in the event that $uid is a full principal name */
	if ($ldap_groups_strip_realm) {
		list($uid, $realm) = split('@', $uid);
	}
	/* uid's are stored all lowercase, and memberUid is caseExactMatch */
	$uid = strtolower($uid);

	/* find the DN of the user */
	$search_filter = "(&(objectClass=$ldap_user_objectclass)($ldap_user_attr=$uid))";
	$sr = ldap_search($ldapconn, $ldap_base, $search_filter, array("dn"), 0, 0);
	$results = ldap_get_entries($ldapconn, $sr);
	$userDN = $results[0]['dn'];
	
	/* find the groups that contain our user */
	$search_filter = "(&(objectClass=$ldap_group_objectclass)($ldap_member_attr=$userDN))";

	$sr = ldap_search($ldapconn, $ldap_base, $search_filter, array("$ldap_group_name_attr"), 0, 0);

	$results = ldap_get_entries($ldapconn, $sr);
	
	$groups = array();

	foreach ($results as $entry) {
		if (array_key_exists($ldap_group_name_attr, $entry)) {
			array_push($groups, $entry[$ldap_group_name_attr][0]);
		}
	}

	ldap_close($ldapconn);
	
	return $groups;
}

/* Gets implicit ldap server group membership
 *
 * accepts: $ldap_server spec, user id
 * returns: array of implicit groups if user id exists on $ldap_server
 */
function efLDAP_Groups_get_implicit($ldap_server, $uid) {
	extract($ldap_server, EXTR_PREFIX_ALL, 'ldap');
	
	$ldapconn = ldap_connect($ldap_hostname) or error_log("Could not connect to ldap server.");
	$ldapbind = ldap_bind($ldapconn) or error_log("Could not bind to ldap server $ldap_hostname.");

	/* in the event that $uid is a full principal name */
	list($uid, $realm) = split('@', $uid);
	/* uid's are stored all lowercase, and memberUid is caseExactMatch */
	$uid = strtolower($uid);

	$search_filter = "(uid=$uid)";

	$sr = ldap_search($ldapconn, $ldap_base, $search_filter, array("uid"), 0, 0);

	if (ldap_count_entries($ldapconn, $sr) == 1)	{
		ldap_close($ldapconn);
		return array("$ldap_implicit_group_name");
	}

	return array();
}

/* Checks if a group is allowed
 *
 * accepts: single group name
 * returns: FALSE if we should not add the group
 *          TRUE if we should add the group
 */
function efLDAP_Groups_is_legal($group) {
	global $realm_to_ldap;

	/* don't add the group if it's an implicit group for another realm */
	$implicit_groups = array();
	foreach($realm_to_ldap_server['implicit_group_name'] as $implicit_group_name)	{
		array_push($implicit_groups, $implicit_group_name);
	}
	if (!in_array($group, $implicit_groups)) {
		return true;
	} else {
		error_log("Not adding group $group since it conflicts with implicit group");
		return false;
	}
}

/* Writes groups for a given id to the database
 *
 * accepts: mediawiki user id, groups array
 * returns: nothing
*/
function efLDAP_Groups_write_cache($mId, $groups) {
	$dbw = wfGetDB(DB_MASTER);

	/* first purge the existing cache for mId */
	$dbw->delete('ldap_groups_cache', array('mId' => $mId));

	foreach($groups as $group) {
		$dbw->insert('ldap_groups_cache', array('mId' => $mId, 'cached_group' => $group));
	}
	$dbw->immediateCommit(); // needed this or inserts were being lost
}

/* Reads groups for a given id from the database
 *
 * accepts: mediawiki id
 * returns: array of groups
 */
function efLDAP_Groups_enumerate_from_cache($mId) {
	$groups = array();
	$dbr = wfGetDB(DB_SLAVE);
	
	$res = $dbr->select('ldap_groups_cache', '*', array('mId' => $mId));
	if($res)	{
		while ($row = $dbr->fetchObject($res))	{
			array_push($groups, $row->cached_group);
		}
	}
	
	return $groups;
}
