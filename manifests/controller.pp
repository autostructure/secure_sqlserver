# This class manages sqlserver classes.
# Usage:
# Class['::secure_sqlserver::controller']
#
class secure_sqlserver::controller (
  String $svc_acct,
) {

  # TODO: Convert to 2016 after done w/2017 dev environment...
  #       $instances = $facts['sqlserver_instances']['SQL_2016'].keys
  # NOTE: using 'Down-Level Logon Name' format for usernames.
  $port = 1433
  $service_account = "${facts['domain']}\\${svc_acct}"
  $netbios_user = "${facts['domain']}\\${facts['id']}"
  $fqdn_user = "${facts['fqdn']}\\${facts['id']}"

  ## TODO: Convert code to 2016
  #$instances = $facts['sqlserver_instances']['SQL_2016'].keys
  $instances = $facts['sqlserver_instances']['SQL_2017'].keys

  if empty($instances) {
    fail('secure_sqlserver failure: No instances of SQL Server 2016 were discovered in the sqlserver_instances puppet fact (part of the puppetlabs-sqlserver module).')
  }

  $single_instance = $instances[0]

  notify { 'secure_sqlserver:_controller_msg1':
    message  => "secure_sqlserver::controller: Running in SINGLE_INSTANCE mode: instance=${single_instance}",
    loglevel => warning,
  }

  # need sqlserver_config for sqlserver_tsql commands to enable windows authentication (no passwords required)
  sqlserver::config { $single_instance:
    admin_login_type => 'WINDOWS_LOGIN',
  }

  class { '::secure_sqlserver::secure_instance':
    instance => $single_instance,
  }

  #$databases = $facts['sqlserver_databases']

  #if empty($databases) {
  #  fail('secure_sqlserver failure: No SQL Server 2016 databases were discovered.')
  #}

  #$databases.each |String $current_database| {
  #  # using a define type over class, since we make multiple calls...
  #  ::secure_windows::secure_database { "secure_database_${current_database}":
  #    instance => $single_instance,
  #    database => $current_database,
  #  }
  #}

}
