# This class manages sqlserver logon.
# Usage:
# include secure_sqlserver::logon
#
class secure_sqlserver::logon
{

  # TODO: Convert to 2016 after done w/2017 dev environment...
  # $instances = $facts['sqlserver_instances']['SQL_2016'].keys
  $port = 1433
  $netbios_user = "${facts['domain']}/${facts['id']}"
  $fqdn_user = "${facts['fqdn']}/${facts['id']}"
  $instances = $facts['sqlserver_instances']['SQL_2017'].keys
  $single_instance = $instances[0]

  $instances.each |String $instance| {
    sqlserver::config { $instance:
      admin_login_type => 'WINDOWS_LOGIN',
    }
  }

}
