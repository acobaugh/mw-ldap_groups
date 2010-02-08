DROP TABLE IF EXISTS `ldap_groups_cache`;
CREATE TABLE `ldap_groups_cache` (
  `mId` int(11) NOT NULL,
  `cached_group` varchar(100) NOT NULL default ''
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
