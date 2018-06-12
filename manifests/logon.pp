# This class manages sqlserver logon.
# Usage:
# include secure_sqlserver::logon
#
class secure_sqlserver::logon
{

  $instances = $facts['sqlserver_instances.SQL_2017']
  $netbios_user = "${facts['domain']}\\${facts['id']}"

  sqlserver::config { 'MSSQLSERVER':
    admin_login_type => 'WINDOWS_LOGIN',
  }

}
