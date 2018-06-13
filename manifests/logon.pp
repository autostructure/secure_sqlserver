# This class manages sqlserver logon.
# Usage:
# include secure_sqlserver::logon
#
class secure_sqlserver::logon
{

  #$instances = $facts['sqlserver_instances.SQL_2017']
  $instances_hash = $facts['sqlserver_instances']['SQL_2017']
  $instances = $instances_hash.keys
  $netbios_user = "${facts['domain']}\\${facts['id']}"

  sqlserver::config { 'MSSQLSERVER':
    admin_login_type => 'WINDOWS_LOGIN',
  }

  notify { 'print-instances':
    message => "logon.pp::print-instances...\n${instances}",
  }

  notify { 'print-instances-as-array':
    message => $instances,
  }

}
