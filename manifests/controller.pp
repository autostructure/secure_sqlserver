# This class manages other sqlserver classes.
#
# Usage:
# class { '::secure_sqlserver':
#   svc_acct => '<username>',
# }
#
# TODO: Convert to 2016 after done w/2017 dev environment...
#       $instances = $facts['sqlserver_instances']['SQL_2016'].keys
#
class secure_sqlserver::controller (
  String $svc_acct,
) {

  # NOTE: using 'Down-Level Logon Name' format for usernames.
  $port = 1433
  $service_account = $svc_acct
  $netbios_user = $facts['identity']['user']
  $fqdn_user = $facts['id']

  notify { 'secure_sqlserver:_controller_msg0_debug':
    message  => "users: service_account=${service_account}; netbios_user=${netbios_user}; fqdn_user=${fqdn_user}",
    loglevel => debug,
  }

  ## TODO: Convert code to 2016
  #$instances = $facts['sqlserver_instances']['SQL_2016'].keys
  $instances = $facts['sqlserver_instances']['SQL_2017'].keys

  notify { 'secure_sqlserver:_controller_msg1_warning':
    message  => "***DEVELOPER NOTE*** Using SQL_2017 reference instead of SQL_2016 (FIX REQ'D)!!!",
    loglevel => warning,
  }

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

  # Next, cycle through all the databases and secure them...

  $databases = $facts['sqlserver_databases']

  if empty($databases) {
    # fail('secure_sqlserver failure: No SQL Server 2016 databases were discovered.')
    ::secure_sqlserver::log { 'No SQL Server 2016 databases were discovered.':
      loglevel => warning,
    }

  }

  $databases.each |String $database| {

    ::secure_sqlserver::log { "Securing the '${database}' database...":
      loglevel => notice,
    }

    # using a define type over class, since we make multiple calls...
    ::secure_sqlserver::secure_database { "secure_database_${database}":
      instance => $single_instance,
      database => $database,
    }

  }

}
