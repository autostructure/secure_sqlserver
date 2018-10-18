# This class manages other sqlserver classes.
#
# Usage:
# class { '::secure_sqlserver':
#   svc_acct => '<username>',
# }
#
class secure_sqlserver::controller {

  # NOTE: using 'Down-Level Logon Name' format for usernames.
  $netbios_user = $facts['identity']['user']
  $fqdn_user = $facts['id']
  $svc_acct = lookup('secure_sqlserver::svc_acct')
  $port = empty(lookup('secure_sqlserver::port')) ? {
    false   => lookup('secure_sqlserver::port'),
    default => 1433,
  }

  notify { 'secure_sqlserver:_controller_msg0_debug':
    message  => "port=${port}; svc_acct=${svc_acct}; netbios_user=${netbios_user}; fqdn_user=${fqdn_user}",
    loglevel => info,
  }

  notify { 'secure_sqlserver:_controller_msg1_warning':
    message  => "***DEVELOPER NOTE*** Using SQL_2017 reference instead of SQL_2016 (FIX REQ'D)!!!",
    loglevel => alert,
  }

  $instances = $facts['sqlserver_instances']['SQL_2016'].keys

  if empty($instances) {
    fail('secure_sqlserver failure: No instances of SQL Server 2016 were discovered in the sqlserver_instances puppet fact (part of the puppetlabs-sqlserver module).')
  }

  $single_instance = $instances[0]

  notify { 'secure_sqlserver:_controller_msg1':
    message  => "secure_sqlserver::controller: Running in SINGLE_INSTANCE mode: instance=${single_instance}",
    loglevel => info,
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
      loglevel => info,
    }

  }

  $databases.each |String $database| {

    ::secure_sqlserver::log { "Securing the '${database}' database...":
      loglevel => info,
    }

    # using a define type over class, since we make multiple calls...
    ::secure_sqlserver::secure_database { "secure_database_${database}":
      instance => $single_instance,
      database => $database,
    }

  }

}
